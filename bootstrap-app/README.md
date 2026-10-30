# GhostSlop Root Manager app

GhostSlop connects to the phone's own Android Wireless Debugging service as
ADB shell UID 2000. It can stage and manually trigger the one-boot exploit,
prepare an app-facing root daemon, and grant selected app UIDs access through a
temporary `su` entrypoint.

The app is pinned to the Samsung Galaxy A15 `SM-A156U` on firmware
`A156USQSCEZG1`, Android 16, and kernel `5.15.189-android13-8-33641424`. It
refuses to stage or trigger on a different target. This is a device-specific
research build, not a general root solution.

## Safety and lifetime

- The exploit is started only after tapping **Trigger exploit once** and
  confirming the warning. Staging the files does not run it.
- A failed kernel exploit can panic or reboot the device. The app records the
  attempt by boot ID and refuses another attempt during that boot.
- The app does not unlock the bootloader or flash boot, vbmeta, recovery, or
  system partitions.
- The root daemon, app grants, and `/system/bin/su` overlay last only for the
  current boot. Reboot clears them; trigger the exploit and prepare the
  manager again if you want another session.

## Build

Requirements: Android SDK platform/build-tools 36, Java 17 or newer, Android
NDK r30, and network access for the first Gradle dependency download.

From the parent project directory:

```sh
make NDK_ROOT=/path/to/android-ndk-r30 HOST_TAG=linux-x86_64 \
  a15 g4d g4sh g4exec g4d-su g4su g4mount
cd bootstrap-app
./gradlew assembleDebug
```

The APK is `app/build/outputs/apk/debug/app-debug.apk`. From this directory,
install it with:

```sh
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The build checks each generated native payload against the SHA-256 pinned in
`app/build.gradle.kts`. The checked-in tree contains sources and the Gradle
wrapper, not compiled payloads or an APK. The debug APK is signed with a local
debug key and is not a Play Store release.

## First connection

1. Install and open GhostSlop.
2. Enable **Developer options → Wireless debugging** on the phone.
3. On the phone, open **Wireless debugging → Pair device with pairing code**.
   Enter the displayed pairing port and six-digit code in GhostSlop. Pairing
   starts automatically when both values are entered; GhostSlop then looks up
   the separate ADB connect port over local service discovery.
4. After pairing, the setup fields disappear. GhostSlop saves its ADB key and
   device identity in private app storage. If pairing is revoked or no longer
   works, open the pairing screen again and pair again. The optional connect
   port override is for networks where discovery does not find the service. If
   the saved pairing is present but root status is unknown, GhostSlop retries
   the connection check every five seconds while the app is open. It rediscovers
   the current connect port for each action and retries discovery once after a
   refused connection, so a port from an earlier Wireless Debugging session is
   not reused automatically.

## Start a root session

In the **Exploit** tab:

1. Tap **Check & stage exploit**. The app verifies model, kernel, firmware
   fingerprint, bootloader build, boot state, SELinux state, and ADB shell
   identity before copying hash-pinned files to `/data/local/tmp`.
2. Confirm that the target checks passed. Staging does not run the exploit.
3. Tap **Trigger exploit once** and confirm only when ready to attempt it. The
   app shows a running banner and spinner, streams exploit output, and verifies
   the resulting root shell. Keep GhostSlop open and wait for the result.
4. When successful, the top banner reads **EXPLOIT ACTIVE**. The app hides the
   staging and trigger controls for that boot.

If the banner already says **EXPLOIT ACTIVE**, skip staging and triggering.
Do not try to trigger again after a failed or interrupted attempt in the same
boot. The attempt marker is deliberately retained.

## Grant app root access

In the **Root Manager** tab, while **EXPLOIT ACTIVE** is shown:

1. Tap **Prepare manager** once for this boot. It stages hash-pinned helper
   tools and starts the separate app-facing root daemon. The button disappears
   when GhostSlop detects that preparation succeeded.
2. Tap **Choose apps & enable su**. Select app UID groups and continue. The
   confirmation applies those grants and automatically installs the
   RAM-backed `/system/bin/su` overlay. There is no second enable step.
3. Force-stop and reopen any selected app that was already running. Zygote
   mount namespaces receive the overlay for new app processes.
4. **Check manager status** reports daemon, grant, and overlay state.
   **Test this app's su access** checks GhostSlop's own app process; grant the
   GhostSlop UID and reopen it first if you want this check to return UID 0.
5. **Remove su entrypoint** removes the overlay but keeps the current UID grant
   list. To clear grants, open the app picker, deselect everything, and apply.

Grants are by Linux UID. Packages that share a UID share access. The daemon
checks the requesting process UID against the root-owned list in `/dev` tmpfs.
New `su` requests use the list immediately; a root command already running can
continue until it exits. The manager supports common `su -c command` use, but
not every Magisk-specific or vendor-specific `su` option.

The overlay is a RAM-backed OverlayFS mount in live zygote namespaces. It
preserves `/system/bin` ownership and mode and uses a copy of the manager
client at a firmware-specific executable alias. All of this is volatile and
disappears on reboot. See [`../docs/ROOT-MANAGER.md`](../docs/ROOT-MANAGER.md)
for the implementation and its limits.

## Troubleshooting and compatibility

### A root app still reports “not rooted”

Confirm that the banner says **EXPLOIT ACTIVE**, prepare the manager, select
that app in the UID picker, and reopen the app after the grant. A common root
detector may check for a persistent installation or Magisk files instead of
calling `su`; this manager does not install those files. The GhostSlop self-test
checks the manager app's process only, not another app's compatibility.

### Amaze shows `/` with no files

On the tested phone, Amaze was granted root and its root mode was enabled, but
its root view of `/` still showed an empty listing. Its `MANAGE_EXTERNAL_STORAGE`
app-op was allowed and the Amaze process saw the corrected overlay directory
permissions. Root Checker succeeded on the same boot. That points to an
unresolved Amaze/custom-`su` compatibility issue; it is not evidence that all
root access is broken. Force-stop and reopen Amaze after changing grants, then
check Amaze's root-mode setting. If its view remains empty, report the app
version and relevant GhostSlop log output with an issue. Do not include ADB
pairing codes or private keys.

TeamAmaze has separately tracked an Android 16 empty-listing report involving
`MANAGE_EXTERNAL_STORAGE` being denied. It was fixed in the `release/4.0`
branch by [Amaze PR #4578](https://github.com/TeamAmaze/AmazeFileManager/pull/4578).
Our observed app-op was `allow`, so that specific permission bug is not the
leading explanation unless the installed Amaze build is older or its Android
permission state is stale.

The current Amaze source uses libsu's long-lived root shell and sets
`Shell.FLAG_MOUNT_MASTER`; its root listing path runs `stat -c ... *` and may
fall back to `ls -l`. GhostSlop accepts `--mount-master` and supports an
interactive shell, but the on-device checks so far verified only `su -c id`
and not libsu's persistent-shell protocol. That leaves a concrete
GhostSlop-to-Amaze compatibility gap to test. See the Amaze
[`MainActivity`](https://github.com/TeamAmaze/AmazeFileManager/blob/release/4.0/app/src/main/java/com/amaze/filemanager/ui/activities/MainActivity.java#L779),
[`IRootCommand`](https://github.com/TeamAmaze/AmazeFileManager/blob/release/4.0/app/src/main/java/com/amaze/filemanager/filesystem/root/base/IRootCommand.kt#L60),
and [`ListFilesCommand`](https://github.com/TeamAmaze/AmazeFileManager/blob/release/4.0/app/src/main/java/com/amaze/filemanager/filesystem/root/ListFilesCommand.kt#L102).

### Manager preparation times out

Open **Check manager status**. The shell root session and the app-facing `su`
service are separate. If the app reports that the shell is active but the
app-facing service does not answer, save the log output; do not rerun the
exploit. The failure may be in the guarded launch or service startup path.

### Wireless Debugging no longer connects

Make sure Wireless Debugging is on and both devices share the same local
network. If Android no longer lists GhostSlop under **Paired devices**, pair
again with a fresh pairing code. Clear the optional connect-port override to
use discovery.

## Cleanup

The manager's runtime root state disappears on reboot. After reboot, use
**Clean staged files (after reboot)** in the Exploit tab if you want to remove
the ordinary staged files under `/data/local/tmp`. It preserves the attempt
marker for the current boot. Uninstalling/reinstalling the app may remove its
saved Wireless Debugging identity; it does not restore any root state.

For project-level build instructions and the verified device matrix, see the
[repository README](../README.md).
