# GhostLock A15 research port

This tree contains the device-specific GhostLock research port for the
Samsung Galaxy A15 SM-A156U. The successful run documented here was on
kernel `5.15.189-android13-8-33641424`, firmware `A156USQSCEZG1`.

The repository tracks source and reviewable documentation. It intentionally
does not track compiled binaries, device dumps, experimental run logs, or
retry scripts. The active one-shot launcher is
[`scripts/adb-trigger.sh`](scripts/adb-trigger.sh).

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

## Trigger over ADB

Connect the A15 to the computer and confirm ADB lists it as an online
`device`:

```sh
adb devices -l
```

From this repository, run the launcher with the tested binary:

```sh
./scripts/adb-trigger.sh ./ghostlock-a15
```

With multiple devices connected, set `ADB_SERIAL` to the A15's serial. The
script also accepts the binary path as its first argument or through
`GHOSTLOCK_BIN`.

The launcher checks the model, kernel, clean boot state, SELinux mode, ADB
shell identity, helper files, and local/staged binary hashes. It asks you to
type `TRIGGER`, records one attempt for that boot ID on the computer, stages a
temporary executable under `/data/local/tmp`, and checks the result with
`g4sh`. It never retries or reboots. A kernel panic is still possible; if a
panic cuts off ADB, best-effort cleanup of the staged file may not complete.

The same script can run in Termux if its ADB client is working and can see the
phone. `scripts/termux-trigger.sh` is a compatibility symlink. The current
Termux install reported a missing `_ZNSt6__ndk113__hash_memoryEPKvm` symbol
from `$PREFIX/bin/adb`; that runtime/package mismatch must be repaired first.
Read-only diagnostics are:

```sh
type -a adb
dpkg -s android-tools libc++ | grep -E '^(Package|Version|Status):'
termux-info
```

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
