# Root manager: design, lifecycle, and test status

GhostSlop separates the root session from per-app access. The kernel exploit
creates a temporary root context; the manager daemon then authenticates app
requests using the caller's Linux UID. The app UI is a control plane over the
phone's Wireless Debugging ADB service, which runs commands as shell UID 2000.

## Request path

```text
selected app UID
      │ execs /system/bin/su
      ▼
g4su client ── abstract Unix socket ──► app-facing g4d daemon
                                             │
                                             ├─ checks current-boot UID list
                                             ├─ enters caller mount namespace
                                             └─ runs /system/bin/sh -c as root
```

The daemon obtains the caller credentials from `SO_PEERCRED`. It accepts root,
ADB shell UID 2000, and app UIDs listed in the root-owned
`/dev/ghostlock-g4d.allow` file. That file includes the current kernel boot ID;
requests are denied if the boot ID does not match. The app writes the file to
`/dev` tmpfs, so grants disappear at reboot.

The su client is not setuid and does not change its own identity. It asks the
privileged daemon to run the command only after the daemon has checked the
peer UID. By default, commands run in the caller's mount namespace; the
`-mm`/`--mount-master` option selects the daemon's namespace. The implemented
interface supports common `su -c command` requests. It does not promise full
compatibility with Magisk's daemon, modules, prompts, or vendor-specific
options.

## Why the `/system/bin` overlay exists

This firmware rejects direct execution of the staged app-facing client from
`/data/local/tmp` in app processes. The manager exposes `/system/bin/su` through
a RAM-backed OverlayFS mount in live zygote mount namespaces. On this firmware,
the mount places a copy of `g4su` at `/system/bin/lmkd` and makes
`/system/bin/su` a symlink to that alias, so Android app processes can execute
it. The overlay is installed only in zygote namespaces and leaves the system
partition unchanged.

OverlayFS presents the upper directory metadata for a merged directory. An
earlier `g4mount` build created the upper `/system/bin` directory with mode
`0700`, which prevented apps from traversing it and made their shell launch
fail with `EACCES`. The current helper copies the underlying `/system/bin`
owner, group, and mode to the upper directory. Details and evidence are in
[`DEFEX-SAFEPLACE.md`](DEFEX-SAFEPLACE.md).

The mount helper checks for unexpected existing mounts and supports status,
install, and remove operations. It isolates propagation for the target path
and mounts. Removing the overlay does not erase the UID allowlist; clearing
the app picker does not automatically remove the overlay. Both controls are
independent.

## App workflow and state

The **Exploit** and **Root Manager** tabs have separate jobs:

1. Wireless Debugging pairing creates a private app ADB identity. The
   pairing-code port and six-digit code are used only during pairing; the ADB
   connection port is discovered independently over local service discovery.
2. **Check & stage exploit** verifies the exact device state and copies the
   pinned exploit files. It does not trigger the kernel exploit.
3. **Trigger exploit once** requires confirmation, records an attempt against
   the boot ID, runs the payload, and verifies the root shell. The app refuses
   another attempt within that boot, including after an interrupted attempt.
4. **Prepare manager** stages the manager clients and starts an app-facing
   daemon alongside the existing shell daemon. It does not rerun the exploit.
5. **Choose apps & enable su** applies the selected UID list and installs the
   su overlay in one confirmed action.

New processes inherit the overlay through zygote. Apps that were already
running need to be force-stopped and reopened after the overlay is installed.
Changing a grant affects new `su` requests immediately. A root command already
running can continue until it exits.

The manager app's **Test this app's su access** button runs shell and su checks
from GhostSlop's own Android app process. It does not test the process or
backend of another root app. **Check manager status** reports service, grant,
and overlay state, but cannot establish that a specific app understands this
custom su behavior.

## Confirmed behavior and open compatibility issue

On `SM-A156U`, Android 16 build
`A156USQSCEZG1`, the manager's fresh app process could launch `/system/bin/sh`
and `/system/bin/su`; `su -c "id -u"` returned `0`. Root Checker Basic also
reported root after its UID was granted. These results confirm the tested
request path on this build, not broad root-app compatibility.

Amaze File Manager was granted its UID and its root mode was enabled, but its
root view of `/` showed no files. The app's `MANAGE_EXTERNAL_STORAGE` app-op
was allowed; read-only inspection also showed that Amaze saw the corrected
`/system/bin` metadata and the overlay mount. The listing issue remains
unresolved. Amaze's root explorer may depend on a different su interaction or
its own filesystem browsing behavior. Root Checker succeeding does not settle
that question.

The current Amaze `release/4.0` source initializes a long-lived libsu shell
with `Shell.FLAG_MOUNT_MASTER`, then uses `Shell.su(command).exec()` for root
commands. Its root listing first runs `stat -c '%A %h %G %U %B %Y %N' *` and
may retry with `ls -l`. GhostSlop's client accepts `--mount-master` and has an
interactive-shell mode, but the phone checks recorded so far covered only
short `su -c` commands. That makes persistent-shell/libsu compatibility a
specific unverified area on the GhostSlop side. See Amaze's
[`MainActivity`](https://github.com/TeamAmaze/AmazeFileManager/blob/release/4.0/app/src/main/java/com/amaze/filemanager/ui/activities/MainActivity.java#L779),
[`IRootCommand`](https://github.com/TeamAmaze/AmazeFileManager/blob/release/4.0/app/src/main/java/com/amaze/filemanager/filesystem/root/base/IRootCommand.kt#L60),
and [`ListFilesCommand`](https://github.com/TeamAmaze/AmazeFileManager/blob/release/4.0/app/src/main/java/com/amaze/filemanager/filesystem/root/ListFilesCommand.kt#L102).

Amaze separately fixed an Android 16 empty-listing issue that occurred when
`MANAGE_EXTERNAL_STORAGE` was denied. It was merged into `release/4.0` in
[PR #4578](https://github.com/TeamAmaze/AmazeFileManager/pull/4578), which
closed [issue #4570](https://github.com/TeamAmaze/AmazeFileManager/issues/4570).
Because this device's app-op was observed as `allow`, that specific permission
bug is less likely here unless the installed Amaze build predates the fix or
its permission state is stale.

## Security and limits

- Only use this on a device you own or are authorized to modify.
- This is one-boot root. Reboot ends the root context, daemon, grants, and
  overlay. No boot, vbmeta, recovery, or system partition is modified.
- The kernel exploit can panic or reboot the device. An attempt is deliberately
  limited to once per boot.
- App grants are UID-wide. Android packages sharing one UID share the grant.
- The implementation is pinned to one A156U build. Firmware updates, SELinux
  policy changes, kernel changes, and other Samsung models are untested.
- A working `su` command does not guarantee an app's root file browser,
  remount feature, or Magisk-specific integration will work.

See [`../bootstrap-app/README.md`](../bootstrap-app/README.md) for setup and
recovery steps, and [`A15-ONE-BOOT-RESULT.md`](A15-ONE-BOOT-RESULT.md) for the
exploit run record.
