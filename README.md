# GhostLock A15 research port

This tree contains the device-specific GhostLock research port for the
Samsung Galaxy A15 SM-A156U. The successful run documented here was on
kernel `5.15.189-android13-8-33641424`, firmware `A156USQSCEZG1`.

The repository tracks source and reviewable documentation. It intentionally
does not track compiled binaries, device dumps, experimental run logs, or
retry scripts. The active one-shot launcher is
[`scripts/termux-trigger.sh`](scripts/termux-trigger.sh).

## Verified result

One session-only, one-boot root run completed on this target. Its evidence and
limits are summarized in
[`docs/A15-ONE-BOOT-RESULT.md`](docs/A15-ONE-BOOT-RESULT.md). This is one
successful run, not a reliability estimate. Failed MCAST/PI handoffs have
panicked the kernel; the launcher therefore refuses a second attempt in the
same boot and never reboots automatically.

## Build the tested binary

The known-good build used Android NDK r30. On Linux, provide the NDK path and
host tag explicitly:

```sh
make a15 NDK_ROOT=/path/to/android-ndk-r30 HOST_TAG=linux-x86_64
sha256sum ghostlock-a15
```

The tested binary SHA-256 is:

```text
d4dcc86234d9d8b65f910e31c999bdc6ffad9a8d913705cced522e5c986a7831
```

The launcher rejects any binary whose hash differs. Build outputs are ignored
by Git.

## Termux launcher

The exploit must be invoked in an ADB shell (`uid=2000`, context
`u:r:shell:s0`). Running the exploit or `g4sh` directly as the Termux app
does not provide that identity. The existing `g4d`/`g4sh` helpers must be
present and executable at `/data/local/tmp/a/` on the phone.

First ensure Termux's `adb` works and lists the phone as an online `device`:

```sh
adb devices -l
```

For a Termux-on-the-phone setup, Wireless debugging must be paired and
connected to Termux's ADB client. If Termux ADB cannot connect to itself, run
the launcher from a paired computer instead. ADB must work before the
launcher starts; the current Termux install previously reported a missing
`_ZNSt6__ndk113__hash_memoryEPKvm` symbol from `$PREFIX/bin/adb`, so that
package/runtime mismatch needs to be fixed first. Read-only diagnostics are:

```sh
type -a adb
dpkg -s android-tools libc++ | grep -E '^(Package|Version|Status):'
termux-info
```

After repairing the Termux package set, verify `adb version` and
`adb devices -l` before using the launcher.

To copy the launcher and matching binary from a connected computer into
Downloads:

```sh
adb push scripts/termux-trigger.sh /sdcard/Download/termux-trigger.sh
adb push ghostlock-a15 /sdcard/Download/ghostlock-a15
```

In Termux, enable shared storage if needed, then run:

```sh
termux-setup-storage
bash ~/storage/downloads/termux-trigger.sh ~/storage/downloads/ghostlock-a15
```

The launcher checks the model, kernel, clean boot state, SELinux mode, ADB
shell identity, helper files, and both local and staged binary hashes. It
asks you to type `TRIGGER`, records one attempt for that boot ID, and checks
the resulting session with `g4sh`. It does not retry or reboot. A kernel panic
is still possible.

## Verify a live root session

Use ADB shell to reach the helper:

```sh
adb shell '/data/local/tmp/a/g4sh -c "id"'
```

A successful one-boot session reports `uid=0(root)` with context
`u:r:kernel:s0`. Plain `adb shell id` reports the normal unprivileged shell
user. Calling `/data/local/tmp/a/g4sh` directly in Termux runs as the Termux
app UID and is not a root check; `g4d` accepts root or ADB-shell peers.

The root daemon and SELinux state are volatile. Rebooting ends the session;
this project does not install a boot image or persistent root service.

## License and attribution

See [`LICENSE`](LICENSE). This A15 work is a device-specific port of the
GhostLock research tree; the shared source also retains code needed to build
the other existing target profiles.
