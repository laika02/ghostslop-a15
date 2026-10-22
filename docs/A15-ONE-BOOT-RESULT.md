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

## Scope and limits

This is one successful run, not a success-rate estimate. Another attempt with
the same send counts failed before the verified write stage, and failed
MCAST/PI handoffs have panicked the kernel. A PI consumer return alone is not
proof of a write or root.

The successful session was volatile. No boot image, recovery image, or system
partition was written; the temporary exploit executable was removed after
verification. The `g4d` process and permissive SELinux state lasted only for
that boot and end on reboot.

The Termux launcher was syntax/help checked but has not been run end-to-end.
The Termux ADB binary was observed failing to start because a required C++
runtime symbol was missing. Repair and verify ADB before using the launcher.
