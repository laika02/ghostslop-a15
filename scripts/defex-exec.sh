#!/system/bin/sh
# Run one executable through g4exec's guarded DEFEX pathname alias.
# Invoke from the live root shell with:
#   /system/bin/sh /data/local/tmp/a/defex-exec.sh EXECUTABLE [ARG ...]

DEFEX_ALIAS=/system/bin/lmkd
G4EXEC_HELPER=/data/local/tmp/a/g4exec

if [ "${G4DEFEX_PRIVATE_NS:-0}" != 1 ]; then
  parent_mnt=$(/system/bin/readlink /proc/self/ns/mnt) || exit 1
  if [ -z "$parent_mnt" ]; then
    echo "defex-exec: cannot identify parent mount namespace" >&2
    exit 1
  fi
  G4DEFEX_PARENT_MNT="$parent_mnt" G4DEFEX_PRIVATE_NS=1 \
    exec /system/bin/unshare -m /system/bin/sh "$0" "$@"
fi
current_mnt=$(/system/bin/readlink /proc/self/ns/mnt) || exit 1
if [ -z "${G4DEFEX_PARENT_MNT:-}" ] ||
   [ "$current_mnt" = "$G4DEFEX_PARENT_MNT" ]; then
  echo "defex-exec: unshare did not create a new mount namespace" >&2
  exit 1
fi
unset G4DEFEX_PRIVATE_NS

if [ "$(/system/bin/id -u 2>/dev/null)" != 0 ]; then
  echo "defex-exec: run this from the g4sh root shell" >&2
  exit 1
fi
if [ ! -x "$G4EXEC_HELPER" ]; then
  echo "defex-exec: missing executable helper $G4EXEC_HELPER" >&2
  exit 1
fi
if [ "$#" -eq 0 ]; then
  echo "usage: defex-exec.sh EXECUTABLE [ARG ...]" >&2
  echo "       defex-exec.sh --self-test" >&2
  exit 2
fi
if [ "$1" != "--self-test" ] && [ ! -x "$1" ]; then
  echo "defex-exec: target is not executable: $1" >&2
  exit 1
fi

mount_count() {
  count=0
  while read -r id parent dev root mountpoint options rest; do
    if [ "$mountpoint" = "$DEFEX_ALIAS" ]; then
      count=$((count + 1))
    fi
  done < /proc/self/mountinfo
  echo "$count"
}

pid1_has_alias() {
  while read -r id parent dev root mountpoint options rest; do
    [ "$mountpoint" = "$DEFEX_ALIAS" ] && return 0
  done < /proc/1/mountinfo
  return 1
}

has_shared_mount() {
  [ -r /proc/self/mountinfo ] || return 0
  while read -r id parent dev root mountpoint options optional; do
    case " $optional " in
      *" shared:"*) return 0 ;;
    esac
  done < /proc/self/mountinfo
  return 1
}

if pid1_has_alias; then
  echo "defex-exec: alias already appears in PID 1 mountinfo" >&2
  exit 1
fi

# A root daemon can leave a private /system/bin/lmkd mount in the caller's
# namespace. Keep that inherited layer untouched. First stop mount events from
# propagating out of this new namespace, then let g4exec make it fully private.
# Android's /etc/fstab is absent, so pass both paths. For propagation changes,
# the kernel ignores the source and filesystem type arguments.
if ! /system/bin/mount -t ext4 -o rslave / /; then
  echo "defex-exec: could not isolate mount propagation before staging alias" >&2
  exit 1
fi
if has_shared_mount; then
  echo "defex-exec: shared mounts remain after recursive slave conversion" >&2
  exit 1
fi

before=$(mount_count)
case "$before" in
  ''|*[!0-9]*)
    echo "defex-exec: could not count inherited alias mounts" >&2
    exit 1
    ;;
esac

cleanup() {
  trap - EXIT HUP INT TERM
  count=$(mount_count)
  if [ "$count" -eq "$((before + 1))" ]; then
    if ! /system/bin/umount -l "$DEFEX_ALIAS" 2>/dev/null; then
      echo "defex-exec: could not detach the helper alias" >&2
      return 1
    fi
    count=$(mount_count)
  fi
  if [ "$count" -ne "$before" ]; then
    echo "defex-exec: alias mount count changed unexpectedly (inherited=$before visible=$count)" >&2
    return 1
  fi
  if pid1_has_alias; then
    echo "defex-exec: alias unexpectedly remains visible to PID 1" >&2
    return 1
  fi
  return 0
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! /system/bin/mount --bind "$G4EXEC_HELPER" "$DEFEX_ALIAS"; then
  echo "defex-exec: could not stage helper at $DEFEX_ALIAS" >&2
  exit 1
fi
if [ "$(mount_count)" -ne "$((before + 1))" ]; then
  echo "defex-exec: helper alias count changed unexpectedly" >&2
  exit 1
fi
if [ "$1" = "--self-test" ]; then
  "$DEFEX_ALIAS" --self-test
  exit $?
fi

target=$1
shift
"$DEFEX_ALIAS" "$target" "$@"
exit $?
