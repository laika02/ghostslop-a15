# GhostLock A15 research port

This tree contains the device-specific GhostLock research port for the
Samsung Galaxy A15 SM-A156U. The successful run documented here was on
kernel `5.15.189-android13-8-33641424`, firmware `A156USQSCEZG1`.

The repository tracks source and reviewable documentation. It intentionally
does not track compiled binaries, device dumps, experimental run logs, or
retry scripts. The active one-shot launcher is
[`scripts/adb-trigger.sh`](scripts/adb-trigger.sh).

## Verified result

Three session-only, one-boot root runs have completed on this target. The
EDEADLK-path candidate documented below succeeded twice and failed twice on
separate boots, including one failure followed by an ADB disconnect and
reboot. That is not enough to establish reliability. Evidence and limits are in
[`docs/A15-ONE-BOOT-RESULT.md`](docs/A15-ONE-BOOT-RESULT.md). This is not a
reliability estimate. Failed MCAST/PI handoffs have panicked the kernel; the
launcher refuses a second attempt in the same boot and never reboots
automatically.

## Build the current EDEADLK-path candidate

The current source build uses Android NDK r30. On Linux, provide the NDK path
and host tag explicitly:

```sh
make a15 NDK_ROOT=/path/to/android-ndk-r30 HOST_TAG=linux-x86_64
sha256sum ghostlock-a15
```

The current local candidate SHA-256 pinned by the launcher is:

```text
392b205b05c6eda39f4ecc401109859a38b7d585ff90912e85fdf5861a8a0617
```

This candidate restores GhostLock's intended cyclic PI chain and accepts the
trigger only when `FUTEX_CMP_REQUEUE_PI` returns `-1/EDEADLK` and the waiter
then times out. It also checks the chain's `FUTEX_WAITERS` bit before the
requeue, so a missed owner-queue handoff stops before MCAST. It compiled and
ran once on the phone: the candidate verified the fops overwrite, canary,
reversible data writes, pipe read/write channel, UMH completion, and a fresh
root shell. The current boot session is volatile and ends on reboot. The
previous candidate hash was
`8371b050161b517c4f8797625283b5f8543efd3fa363de69fe96605a07721e43`; it
requeued one waiter successfully, then timed out and failed the fops readback.
That successful requeue did not establish GhostLock's EDEADLK trigger. The
older guarded build hash was
`07d47cebb8b9ce982a8d03376c5be273351b0bd2c175b0940b7cab270c5c633a`; it
rejected the EDEADLK result before MCAST on both attempts. An earlier
successful binary SHA-256 was
`d4dcc86234d9d8b65f910e31c999bdc6ffad9a8d913705cced522e5c986a7831`. The
launcher accepts only the current candidate. Build outputs are ignored by Git.

## Trigger over ADB

Connect the A15 to the computer and confirm ADB lists it as an online
`device`:

```sh
adb devices -l
```

From this repository, run the launcher with the EDEADLK-path candidate:

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
`g4sh`. On an unattempted boot it removes a leftover staged file only when its
hash matches the pinned candidate, then stages the verified binary. It prints
a copyable root-check command and interactive fish-shell instructions after
verifying root. It never retries or reboots.
A kernel panic is still possible; if a panic cuts off ADB, best-effort cleanup
of the staged file may not complete.

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

## Shell terminal behavior

`g4sh` and `g4d` have a versioned terminal protocol that carries terminal
dimensions, `TERM`/`TERMINFO`, and resize events. Build and deploy both from
the same revision; the updated client cannot talk to an older daemon. The new
pair was tested on-device through a separate `@ghostlockd_ptytest` socket; the
existing `@ghostlockd` service was left running. The PTY and arrow-key check
passed for one interactive `nnn` session. See
[`docs/G4SH-PTY.md`](docs/G4SH-PTY.md) for details.

The observed Termux execution restriction and temporary bind-mount result are
recorded in [`docs/DEFEX-SAFEPLACE.md`](docs/DEFEX-SAFEPLACE.md). The new
`g4exec` helper and `scripts/defex-exec.sh` provide a guarded, one-command
launcher that checks a private mount namespace and cleans its overlays. Its
disposable-file self-test and one Termux binary launch passed on this boot;
`/system/bin/lmkd` is the only path tested on this firmware. Do not pass
untrusted executables. This manual helper does not replace the existing
`umh_root.c` daemon startup sequence.

From the live g4sh root shell, source the small function once, then use
`g4run` to resolve names from Termux's `bin` directory first, then the shell
`PATH`:

```sh
. /data/local/tmp/a/g4run-init.sh
g4run nnn /data
g4run fish
```

The fish launcher sources `scripts/g4run-fish-init.fish`, which wraps Termux
executables so ordinary fish commands also go through the DEFEX helper. It
overrides default fish functions such as `ls` when a Termux executable has the
same name, while leaving fish builtins intact. The temporary alias mounts are
detached immediately after each executable starts, so fish can call the wrapper
again for later commands. Run this inside the root g4sh session; launching it
directly from the Termux app UID is not authorized by g4d.

## License and attribution

See [`LICENSE`](LICENSE). This A15 work is a device-specific port of the
GhostLock research tree; the shared source also retains code needed to build
the other existing target profiles.
