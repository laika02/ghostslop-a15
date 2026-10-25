# Samsung DEFEX SafePlace observations

## Device scope

These observations are from a Galaxy A15 5G SM-A156U running firmware
`A156USQSCEZG1`, Android 16, and kernel
`5.15.189-android13-8-33641424`. They describe one device and firmware build;
they do not establish behavior on other Samsung devices or updates.

## Observed behavior

The user reported a live `g4sh` session with UID 0, GID 0, effective
capabilities reported as full, SELinux permissive, and context
`u:r:kernel:s0`. Despite that state, attempts to execute Termux's `grep` and
`coreutils` were killed with status 137. The device log contained:

```text
[DEFEX] Safeplace violation [task=sh (/system/bin/sh), child=/data/data/com.termux/files/usr/bin/grep, uid=0]
[DEFEX] Safeplace violation [task=sh (/system/bin/sh), child=/data/data/com.termux/files/usr/bin/coreutils, uid=0]
```

The user also reported that invoking a Termux binary through
`/system/bin/linker64` did not avoid the failure.

A temporary bind mount was reported to let `nnn` execute when it was presented
under `/system/bin/lmkd`:

```sh
mount --bind /data/data/com.termux/files/usr/bin/nnn /system/bin/lmkd
/system/bin/lmkd /data
```

The `nnn` process launched with UID 0. This is a reported runtime observation;
it does not prove the exact pathname lookup or policy decision made by the
vendor kernel. No system partition was rewritten for this experiment.

## Existing daemon launcher

`src/core/umh_root.c:handle_umh_mode()` contains a related session-only
launcher. It invokes a shell that bind mounts
`/data/local/tmp/a/g4d` over `/system/bin/lmkd`, starts the daemon through that
path, attempts one lazy unmount, and removes the daemon PID file. A similar
launcher sequence is present in `src/core/main.c`.

The existing `handle_umh_mode()` path does not create a new mount namespace,
set recursive private propagation, inspect for an existing overlay, or verify
cleanup. It also falls back to executing `g4d` at its data path if the bind
mount fails. The one-shot `umount -l` does not account for an already stacked
set of mounts. That existing launcher must not be treated as mount-isolated.

The new `scripts/defex-exec.sh` and `src/daemon/g4exec.c` provide a separate,
guarded path for an explicitly selected executable. The script enters a new
mount namespace, refuses an existing `/system/bin/lmkd` overlay, temporarily
bind mounts `g4exec` at that alias, then lets `g4exec` set recursive private
propagation and verify it before adding the target overlay. The helper checks
mountinfo and `/proc/1/mountinfo`, refuses stacked aliases, and removes both
its target and helper overlays as soon as the target's `execve` succeeds. This
allows a long-running target such as fish to launch later commands through a
fresh helper invocation. The shell wrapper limits fallback cleanup to the
mounts it created. This is still device-specific and must pass the disposable
mount self-test before use; it is not a general su manager.

The user observed different mount namespace IDs for `g4sh` and PID 1. Their
mountinfo showed several `/system/bin/lmkd` overlays in the shell's namespace
and none in PID 1's. This is useful device evidence, but namespace IDs alone do
not describe mount propagation. Android Toybox `mount` also rejected the
util-linux `--make-rprivate` option in the reported session.

## Isolation status and limits

The new helper verifies that `unshare -m` changed the mount namespace, makes
the new namespace recursively private with `MS_REC|MS_PRIVATE`, and checks
`mountinfo` before running a target. It refuses a pre-existing alias, checks
that the alias is absent from PID 1's mountinfo, and cleans the two expected
mount layers on normal exit and catchable signals. Its disposable self-test
passed on this firmware.

The `/system/bin/lmkd` alias is a critical daemon path and was used only as a
tested example. The helper cannot clean up after `SIGKILL` or a kernel crash;
the namespace isolates any leftover mount from PID 1, and it disappears when
all processes in that namespace exit. Bind mounting does not rewrite the
system partition, but an overlay left in the active namespace can still change
later process launches there. Do not pass untrusted executables through a root
process.

The default `umh_root.c` daemon-start path remains unchanged and does not use
this helper. A future integration should keep the namespace checks and cleanup
fail-closed, and should identify a less sensitive trusted alias before using
the launcher more broadly.

## Runtime helper trial (2026-10-25)

The helper was built with Android NDK r30 and exercised on boot ID
`7fa6687b-4cd5-46e0-9b5e-9613c54ae845` without rerunning the kernel exploit.
The disposable-file self-test passed: it made the helper namespace recursively
private, bind-mounted two temporary files, verified the mount was absent from
PID 1's mountinfo, detached it, and removed both files.

The guarded launcher then ran Termux `grep --version` through
`/system/bin/lmkd`; GNU grep 3.12 printed its version and exited successfully.
This confirms the helper's path-based launch works for that binary on this
boot.

A separate test daemon was launched through the same helper as
`g4d-ptytest`, listening on `@ghostlockd_ptytest`. Its mount namespace was
`mnt:[4026534829]`, with no `/system/bin/lmkd` mount after startup. During the
`nnn` run, process 4049 had UID 0 in namespace `mnt:[4026534888]`. Its
mountinfo showed the expected two temporary alias layers (the helper and then
`nnn`); PID 1's mountinfo had no alias entry. After `q`, checks found no alias
in the daemon namespace or PID 1, and the disposable probe files were absent.
The device remained on the same boot ID. No system partition was rewritten.

The tested invocation was:

```sh
HOME=/data/data/com.termux/files/home \
  /system/bin/sh /data/local/tmp/a/defex-exec.sh \
  /data/data/com.termux/files/usr/bin/nnn /data
```

`TERM` and `TERMINFO` were set when starting the matching test client. This is
one successful device session, not a reliability claim. The default
`umh_root.c` launch sequence remains unchanged; the guarded launcher is a
separate manual path after one-boot root is available.

## Wrapped fish shell trial (2026-10-25)

From the live root `g4sh` shell, the user sourced the shell function and
started fish with:

```sh
. /data/local/tmp/a/g4run-init.sh
g4run fish
```

Fish reported root identity (`uid=0(root)`) through the wrapped `id` command.
The initial `ls` command exited 137. Kernel logs showed DEFEX killing
`/data/data/com.termux/files/usr/bin/coreutils`. Fish had a default `ls`
function, and the first version of `g4run-fish-init.fish` skipped command names
that already had a fish function, so that function launched Termux `coreutils`
directly.

The init file was changed to wrap matching Termux executables even when fish
already has a function of that name, while continuing to leave fish builtins
alone. After reloading the updated init file in the active fish session, the
user confirmed `ls /` worked. This validates the fish command wrapper for
`id` and `ls` in this session; it does not establish that programs which launch
their own Termux child processes will also work through the wrapper.
