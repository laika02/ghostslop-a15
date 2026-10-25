# A15 one-boot root result

Date: 2026-10-21
Device: Samsung Galaxy A15 SM-A156U
Firmware: `A156USQSCEZG1`
Kernel: `5.15.189-android13-8-33641424`

## Outcome

One session-only run started from an enforcing, unrooted ADB-shell state and
left a usable root daemon for the rest of that boot. Fresh ADB commands through
`/data/local/tmp/a/g4sh` returned UID 0 with context `u:r:kernel:s0`; ordinary
`adb shell id` remained UID 2000.

The exploit process verified the MCAST/PI handoff, the fake ashmem fops
pointer, and an owned-page canary. A boot-ID data word was written, read back,
restored, and verified. The direct pipe-channel self-test also verified a
write/read/restore sequence. The UMH work item completed with `wake=1`,
`complete=1`, and `retval=0`, then launched the existing `g4d` daemon.

## Tested build and invocation

The AArch64 binary was built with Android NDK r30. It was 238,072 bytes and
had SHA-256:

```text
d4dcc86234d9d8b65f910e31c999bdc6ffad9a8d913705cced522e5c986a7831
```

The successful ADB-shell invocation was:

```sh
SLIDE_USE_TRACEFS=1 A15_MCAST_FOPS_ROUTE=1 A15_SESSION_ONLY=1 \
  A15_MCAST_PRESPRAY_SENDS=144 A15_MCAST_RECLAIM_SENDS=16 \
  /data/local/tmp/ghostlock-a15-session/e
```

Post-run verification used fresh commands:

```sh
adb shell '/data/local/tmp/a/g4sh -c "id"'
adb shell '/data/local/tmp/a/g4sh -c "id -u"'
```

Expected successful output includes:

```text
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
0
```

## Follow-up attempt (2026-10-25)

Device build: `samsung/a15xsq/a15x:16/BP4A.251205.006/A156USQSCEZG1:user/release-keys`
Security patch: `2026-07-05`
Kernel: `5.15.189-android13-8-33641424`
Binary SHA-256: `d4dcc86234d9d8b65f910e31c999bdc6ffad9a8d913705cced522e5c986a7831`
Boot ID before attempt: `d82190e5-c297-40c4-ac8a-1fe3f0e1f870`
Boot ID after recovery: `2babcbc8-74f3-4d1b-9f45-e45fcb62089f`

Only one exploit invocation was made. The non-interactive launcher stopped at
its confirmation prompt, and a later preflight refused to overwrite an old
staged binary. That staged file matched the known build hash, so it was removed
before the actual run.

The actual run verified the tracefs slide, accepted all 144 MCAST prespray
sends, prepared the kernel page, and completed the heap spray. Output then
stopped during the MCAST fops redirect. The launcher returned status 255 from
the exploit/ADB command and could not verify root through `g4sh`. ADB
disconnected during the attempt. After reconnect, the device had booted with a
new boot ID, `sys.boot_completed=1`, and both `ro.boot.bootreason` and
`sys.boot.reason` reported only `reboot`. Those generic reasons do not confirm
whether the device hit a kernel panic. A Samsung bugreport collected afterward
did retain crash evidence: its AEE history lists two kernel-oops records at
08:16:23 and 08:19:33 local, both at
`rt_mutex_adjust_prio_chain+0x1ac/0x14cc`. The last-kernel log shows a NULL
pointer read at address 0 in that function during `sched_setattr`, with
`x27=0`. This matches the previously observed PI-waiter `lock`-field failure.
The first record is consistent with the failed trigger; the launcher did not
retry or reboot the phone, and the available evidence does not establish why a
second oops was recorded three minutes later.

After reconnect, ordinary `adb shell id` reported UID 2000 and
`g4sh -c id` reported that `g4d` was not reachable. The staged exploit binary
was removed. No root session was verified for this attempt; it is a failed
run, not another success. The launcher did not retry or reboot the phone.
The full bugreport is not tracked in this repository; only the relevant crash
summary is retained here.

## PI handoff audit (2026-10-25)

Static review found a handoff race in `src/core/slide.c`: the waiter publishes
`slide_waiter_waiting` immediately before entering `FUTEX_WAIT_REQUEUE_PI`.
The parent can issue `FUTEX_CMP_REQUEUE_PI` before the waiter reaches the
kernel wait queue. The syscall result is therefore needed to distinguish a
missed handoff from the intended trigger.

The intended GhostLock trigger is the cyclic PI chain: the waiter owns
`slide_f_pi_chain`, the target owner holds `slide_f_pi_target` and waits on the
chain, and requeueing the waiter to the target attempts to form a cycle. The
expected result is `-1/EDEADLK`. Original port notes identify this rollback as
the path that leaves the stack waiter available to the later MCAST/PI trigger.
The previous source change incorrectly treated this cycle as something to
remove and treated a successful requeue count of one as the expected path.

The Android Common Kernel 5.15 reference source helps distinguish the two
paths. A successful requeue followed by timeout enters
`rt_mutex_cleanup_proxy_lock()` and removes the PI waiter. On a requeue
deadlock, the requeue state is reset and the waiter remains on the source
futex queue until its timeout; that path does not enter the later
`Q_REQUEUE_PI_DONE` timeout cleanup. The initial failed proxy-lock attempt
still performs its own rollback, and Samsung's exact behavior there has not
been confirmed. See [Android Common `kernel/futex/core.c`](https://android.googlesource.com/kernel/common/+/refs/tags/android13-5.15-2026-06_r4/kernel/futex/core.c#2390),
[proxy-lock cleanup](https://android.googlesource.com/kernel/common/+/refs/tags/android13-5.15-2026-06_r4/kernel/locking/rtmutex_api.c#394),
and [waiter removal](https://android.googlesource.com/kernel/common/+/refs/tags/android13-5.15-2026-06_r4/kernel/locking/rtmutex.c#1461).

The exact Samsung source for this firmware was not available through the OSRC
lookup. The A15 still reports kernel `5.15.189-android13-8-33641424`, so the
Android Common source is a reference, not proof of the device's vendor-patched
rollback behavior.

The first guarded candidate was compiled with Android NDK r30 for API 35. Its
SHA-256 was
`07d47cebb8b9ce982a8d03376c5be273351b0bd2c175b0940b7cab270c5c633a`. It was
not the previously successful binary.

### Guarded handoff attempt

The first launcher invocation used piped confirmation; ADB preflight consumed
the input and the script exited before creating the per-boot marker or staging
the binary. Those states were checked before continuing. One interactive
launcher-triggered attempt then used the candidate on boot ID
`2babcbc8-74f3-4d1b-9f45-e45fcb62089f`. The tracefs slide and heap preparation
completed, including all 144 MCAST prespray sends. The log reported
`FUTEX_CMP_REQUEUE_PI ret=-1 errno=35` (`EDEADLK`),
`FUTEX_WAIT_REQUEUE_PI ret=-1 errno=110` (`ETIMEDOUT`), and chain unlock
`ret=0 errno=0`. The guard rejected the MCAST/PI stage before the MCAST stack
copy. The launcher returned status 255 and did not verify root.

The phone remained online with the same boot ID and completed boot state,
SELinux enforcing, and shell UID 2000. `g4sh` reported that `g4d` was not
reachable, and the staged binary was removed. No reboot or panic was observed
in this attempt; no retry was made, and the launcher marker prevents another
attempt on this boot.

At the user's request, the phone was rebooted to obtain a fresh one-attempt
window, then the same guarded candidate was run once on boot ID
`f4a26438-bf3b-4bfc-850f-639b0daeecde`. It again reported requeue
`ret=-1 errno=35` (`EDEADLK`) and wait `ret=-1 errno=110` (`ETIMEDOUT`); the
guard stopped before the MCAST stack copy. The launcher returned status 255
and did not verify root. The phone remained online on the same new boot, with
SELinux enforcing and shell UID 2000; the staged binary was removed. No
further attempt was made on that boot.

The earlier guard expected a successful requeue count of one. Candidate
`8371b050161b517c4f8797625283b5f8543efd3fa363de69fe96605a07721e43` added a
separate chain holder, eliminating the intentional cycle. It produced
`FUTEX_CMP_REQUEUE_PI ret=1`, then the waiter timed out on the target. The
MCAST copy ran and `sched_setattr` returned success, but fops readback was
zero and the canary was not written. This run confirms that a successful
requeue is not enough for the GhostLock trigger.

### Revised ordering attempt

After a reboot, the revised candidate was run once on boot ID
`793297eb-f141-4dee-a286-934ae5a7839e`. The chain-wait check passed and
`FUTEX_CMP_REQUEUE_PI` returned `1`; `FUTEX_WAIT_REQUEUE_PI` then timed out as
expected. The MCAST `setsockopt` copy was accepted, and the PI consumer's
`sched_setattr` returned success.

This still did not verify the target write. The fops pointer readback returned
zero, and the fallback configfs `pwrite` failed with `EINVAL`; the canary was
not written or read back. The exploit reported “target write remains
unverified" and paused intentionally to keep its payload pages alive and skip
another trigger. A fresh `g4sh -c id` check reported that `g4d` was
unreachable. The phone remained online on the same boot with SELinux enforcing
and shell UID 2000; no reboot or panic was observed. The `ret=1` requeue was a
different path from GhostLock's intended `EDEADLK` rollback trigger.

The paused exploit process was still running as PID 11701. The launcher could
not reach its normal exit cleanup while the remote command remained paused, so
the staged executable was manually unlinked from `/data/local/tmp`; the process
continued running and retained the payload pages. No retry was made on this
boot. This run's successful requeue is not evidence that the intended
`EDEADLK` rollback trigger fired, and it produced no verified write or root.

### EDEADLK-path candidate run (2026-10-25)

The user requested one reboot and one run of the candidate. The prior paused
process was cleared by that reboot. The fresh boot ID was
`216f2321-5d50-4c3e-ba6b-b17c692fb8c0`; before the run, boot was complete,
SELinux was Enforcing, ordinary ADB shell UID was 2000, and `g4sh` could not
reach a root daemon.

The candidate was built with Android NDK r30 for API 35. It is 239,192 bytes
with SHA-256
`392b205b05c6eda39f4ecc401109859a38b7d585ff90912e85fdf5861a8a0617`. The
guarded launcher staged that hash and invoked it once with:

```sh
SLIDE_USE_TRACEFS=1 A15_MCAST_FOPS_ROUTE=1 A15_SESSION_ONLY=1 \
  A15_MCAST_PRESPRAY_SENDS=144 A15_MCAST_RECLAIM_SENDS=16 \
  /data/local/tmp/ghostlock-a15-session/e
```

The run verified tracefs slide 0, accepted all 144 prespray sends, and
prepared the kernel page. The intended trigger occurred:
`FUTEX_CMP_REQUEUE_PI ret=-1 errno=35` (`EDEADLK`), followed by
`FUTEX_WAIT_REQUEUE_PI ret=-1 errno=110` (`ETIMEDOUT`). MCAST returned
`-1/EADDRNOTAVAIL` after the copy, and the consumer's `sched_setattr` returned
0. The fops pointer readback matched the planned fake fops pointer (8 bytes).
The owned-page configfs canary write and read each returned 35 bytes. The
boot-ID data-pointer operation read back the planned value and restored the
original boot ID data. The direct configfs pipe channel then passed its
read/write/restore self-test. The UMH work item completed with
`wake=1 complete=1 retval=0` and reached the root helper.

The exploit's g4sh check printed
`uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0`. A fresh
post-run ADB check independently ran `/data/local/tmp/a/g4sh -c id` and
`g4sh -c "id -u"`; they returned UID 0. `/proc/net/unix` showed the active
`@ghostlockd` socket. Ordinary `adb shell id` remained UID 2000, and
`getenforce` reported Permissive. The boot ID remained
`216f2321-5d50-4c3e-ba6b-b17c692fb8c0`. The staged exploit executable was
absent after launcher cleanup. No boot image, system, or recovery partition
was written. This is a volatile root session and will end on reboot.

The launcher initially printed a false negative because it compared all of
g4sh's echoed `id -u` transcript with the single string `0`. The independent
g4sh checks above confirmed root. `scripts/adb-trigger.sh` now extracts an
exact numeric `0` line from that transcript before deciding whether root was
verified. The updated parser was syntax-checked locally; it was not used for
this run.

The run verifies a one-boot root session and the write/channel stages for
this attempt. It does not establish a success rate or explain every prior
panic. The exact Samsung `EDEADLK` rollback source remains unavailable, and
the MCAST stack offset/reclaim path may still fail on another boot.

### Same-candidate reliability trial 2

After the user requested a repeat, the same candidate hash was run on a fresh
boot, `0eaacf3a-aa45-4add-a636-e338745441c4`. The staged device executable was
read back and matched SHA-256
`392b205b05c6eda39f4ecc401109859a38b7d585ff90912e85fdf5861a8a0617`.
The supplied transcript reports that the MCAST PI consumer syscall returned
success, but the fops probe returned zero bytes with value zero instead of the
planned pointer. The owned-page configfs canary write failed with `EINVAL`,
and the exploit stopped while holding payload pages. This is a failed write
attempt; the syscall return is not success evidence.

Read-only checks afterward found the same boot ID, ordinary shell UID 2000,
SELinux Enforcing, and `g4sh` unreachable. PID 4859 remained paused in
`rt_sigsuspend`, and `/data/local/tmp/ghostlock-a15-session/e` remained staged
with the candidate hash. No second trigger was made and the process/file were
left alone. The candidate has now produced one verified root session and one
failed write attempt on separate boots; this is too little data to estimate a
stable success rate, and the observed failure shows it is not reliable yet.

### Launcher stale-stage handling

On boot `dfd0a6a3-c63f-4b9c-a02c-29df1a0db993`, a launcher invocation stopped
before staging or creating its per-boot attempt marker because the previous
run's `/data/local/tmp/ghostlock-a15-session/e` still existed. Read-only checks
confirmed the new boot was complete, SELinux Enforcing, shell UID 2000, no
matching exploit process, and the staged file hash matched the pinned
candidate. The stale temporary file was removed; no exploit attempt occurred
on this boot.

The launcher now removes a pre-existing staged executable on an unattempted
boot only when its hash matches the pinned candidate. It still refuses an
unknown staged file and any boot ID already marked as attempted. On root
verification, it prints a copyable `g4sh` command. The script was then run
after the stale file had been manually removed; it did launch the candidate,
but the attempt failed as recorded below. That run did not exercise the new
stale-file removal branch, and the success-only `g4sh` command output has not
been observed yet.

### Same-candidate reliability trial 3

On boot `dfd0a6a3-c63f-4b9c-a02c-29df1a0db993`, the user reran the same
candidate after the stale staged file had been cleared. The launcher reported
exploit/ADB status 255 and did not verify root. ADB disconnected; after it
returned, the phone had boot ID
`7fa6687b-4cd5-46e0-9b5e-9613c54ae845`, boot complete, SELinux Enforcing,
ordinary shell UID 2000, and `g4sh` unreachable. Both boot-reason properties
reported `reboot`, which does not establish whether this was a kernel panic.
The shell could not read `/sys/fs/pstore`. The staged executable remained and
its hash still matched the candidate; no exploit process remained after the
reboot. No further trigger was run.

The current candidate has one verified success and two failed runs on separate
boots at this point in the timeline. The third run caused an ADB disconnect and
reboot, but available read-only evidence cannot confirm the cause.

### Same-candidate reliability trial 4

On the following boot, `7fa6687b-4cd5-46e0-9b5e-9613c54ae845`, the user ran
the same candidate through the updated launcher. The launcher removed the
leftover staged file, ran the one-shot attempt, verified root, and printed the
copyable g4sh command. The local per-boot marker exists. The candidate hash
remained `392b205b05c6eda39f4ecc401109859a38b7d585ff90912e85fdf5861a8a0617`.

Fresh read-only checks confirmed boot complete, SELinux Permissive, ordinary
ADB shell UID 2000, and `/data/local/tmp/a/g4sh -c id` returning
`uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0`. A separate
`g4sh -c "id -u"` returned `0`, `/proc/net/unix` showed `@ghostlockd`, and the
staged exploit executable was absent after cleanup. No further attempt was
made on this boot. This records a second success and fourth trial for the same
candidate, with two intervening failed runs.

## Scope and limits

Three successful one-boot root sessions are recorded across the broader work,
but this is not a reliability estimate. For the current candidate hash, two
fresh-boot attempts succeeded and two failed; one failure was followed by an
ADB disconnect and reboot of unknown cause. Other attempts with the same send
counts failed, and failed MCAST/PI handoffs have panicked the kernel. A PI
consumer return alone is not proof of a write or root.

The successful session was volatile. No boot image, recovery image, or system
partition was written; the temporary exploit executable was removed after
verification. The `g4d` process and permissive SELinux state lasted only for
that boot and end on reboot.

The Termux launcher was syntax/help checked but has not been run end-to-end.
The Termux ADB binary was observed failing to start because a required C++
runtime symbol was missing. Repair and verify ADB before using the launcher.
