# GhostSlop A15 Root Manager

GhostSlop is an experimental, one-boot root manager for one Samsung Galaxy A15
firmware build. It uses a manually triggered kernel exploit to open a root
session, then lets you grant selected app UIDs access through a temporary
`su` entrypoint.

This project is for device-owner research on the exact supported build below.
It is not Magisk, does not unlock the bootloader, and does not install
persistent root. A failed kernel exploit can still panic or reboot the phone.

## Supported device

The app checks all of these values before staging the exploit:

| Property | Supported value |
| --- | --- |
| Model | `SM-A156U` |
| Kernel | `5.15.189-android13-8-33641424` |
| Firmware fingerprint | `samsung/a15xsq/a15x:16/BP4A.251205.006/A156USQSCEZG1:user/release-keys` |
| Bootloader build | `A156USQSCEZG1` |

Do not try the payload on another model or firmware. The app refuses a
mismatch, and this project makes no compatibility claim for other devices.

## What has been confirmed

- A one-boot root session and the app-facing `su` daemon work on the supported
  A156U build.
- Root Checker Basic received UID 0 after its UID was granted.
- The app's own `su` self-check succeeded after preparing the manager, granting
  the manager app's UID, installing the overlay, and reopening the app.
- Amaze File Manager was granted root, but its root view of `/` showed an empty
  listing. This is still under investigation; the result does not establish
  that Amaze can use this custom `su` implementation.

The test evidence and device-specific engineering notes are in
[`docs/A15-ONE-BOOT-RESULT.md`](docs/A15-ONE-BOOT-RESULT.md),
[`docs/DEFEX-SAFEPLACE.md`](docs/DEFEX-SAFEPLACE.md), and
[`docs/ROOT-MANAGER.md`](docs/ROOT-MANAGER.md).

## Build and install

Build requirements: Linux, Android SDK platform/build-tools 36, Java 17 or
newer, and Android NDK r30. Gradle downloads its declared dependencies on the
first build.

From the repository root, set `NDK_ROOT` to your NDK directory and `HOST_TAG`
to the NDK host directory for your system:

```sh
make NDK_ROOT=/path/to/android-ndk-r30 HOST_TAG=linux-x86_64 \
  a15 g4d g4sh g4exec g4d-su g4su g4mount
cd bootstrap-app
./gradlew assembleDebug
```

The debug APK is written to
`bootstrap-app/app/build/outputs/apk/debug/app-debug.apk`. From the repository
root, install it with:

```sh
adb install -r bootstrap-app/app/build/outputs/apk/debug/app-debug.apk
```

The Gradle command runs from `bootstrap-app`. Native payload hashes are pinned
in the app build; a changed or mismatched payload is rejected instead of being
packaged. The repository does not track generated binaries or debug APKs.

## Use the manager

The app has separate **Exploit** and **Root Manager** tabs. The manager can
only prepare app access after a root session is active. For the full steps,
recovery notes, and known app compatibility issues, read
[`bootstrap-app/README.md`](bootstrap-app/README.md) and
[`docs/ROOT-MANAGER.md`](docs/ROOT-MANAGER.md).

At a glance:

1. Enable **Developer options → Wireless debugging**. On first pairing, open
   Android's **Pair device with pairing code** screen. Enter the pairing port
   and six-digit code in GhostSlop; it pairs and discovers the connection port
   automatically.
2. In **Exploit**, tap **Check & stage exploit**. This validates the device and
   stages the files; it does not run the exploit.
3. Tap **Trigger exploit once** only if you intend to run the one-shot attempt.
   The app asks for confirmation and will not retry within the same boot.
4. When the banner says **EXPLOIT ACTIVE**, open **Root Manager** and tap
   **Prepare manager**.
5. Tap **Choose apps & enable su**, select app UID groups, and apply. The app
   writes the current-boot grants and installs the RAM-backed `su` overlay.
6. Force-stop and reopen selected apps that were already running. Use **Check
   manager status** or **Test this app's su access** to inspect the manager.

## What changes at runtime

The manager is volatile. The UID grant list lives in `/dev` tmpfs, and the
`/system/bin/su` entrypoint is exposed through an overlay in live zygote mount
namespaces. Reboot clears the daemon, grants, and overlay. Wireless Debugging
pairing credentials are stored in the app's private data so the app can try to
reconnect; Android may still require pairing again if that pairing is revoked
or unavailable. If a saved pairing exists but root status is unknown, GhostSlop
rechecks every five seconds while it is open and stops once status is known. It
pauses those retries when the app is in the background. Wireless Debugging's
connect port is rediscovered for each action; if a connection is refused,
GhostSlop refreshes discovery once before reporting the failure.

The app's allowlist is by Linux UID. Packages sharing a UID share a grant.
Selecting an app does not show a separate approval dialog in that app: access
is controlled by the list you apply in GhostSlop. Common `su -c command` usage
is supported; some root apps expect Magisk-specific interfaces or options and
may not work.

No boot, vbmeta, recovery, or system partition is flashed or patched. The
kernel exploit itself can crash the running kernel; keep important data backed
up and use only on a device you own and are authorized to modify.

## Repository map

- `bootstrap-app/` — Android Wireless Debugging bootstrap and root manager.
- `src/daemon/` — root daemon, `su` client, mount manager, and shell client.
- `src/core/` — device-specific kernel exploit research source.
- `scripts/` — ADB trigger and guarded DEFEX execution helpers.
- `docs/` — exploit results, root-manager architecture, and compatibility
  findings.

The exploit history and lower-level build/trigger process are documented in
[`docs/A15-ONE-BOOT-RESULT.md`](docs/A15-ONE-BOOT-RESULT.md). The terminal
protocol and Termux helper notes are in [`docs/G4SH-PTY.md`](docs/G4SH-PTY.md)
and [`docs/DEFEX-SAFEPLACE.md`](docs/DEFEX-SAFEPLACE.md).

## License

See [`LICENSE`](LICENSE) and the notices for the bundled ADB library in
[`bootstrap-app/adb-kt/NOTICE.md`](bootstrap-app/adb-kt/NOTICE.md).
