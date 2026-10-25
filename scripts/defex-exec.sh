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

before=$(mount_count)
if [ "$before" -ne 0 ]; then
  echo "defex-exec: refusing pre-existing/stacked alias ($before mount(s))" >&2
  exit 1
fi
if pid1_has_alias; then
  echo "defex-exec: alias already appears in PID 1 mountinfo" >&2
  exit 1
fi

cleanup() {
  trap - EXIT HUP INT TERM
  count=$(mount_count)
  if [ "$count" -gt 2 ]; then
    echo "defex-exec: leaving $count alias mounts untouched; ownership unclear" >&2
    return 1
  fi
  attempt=0
  while [ "$count" -gt 0 ] && [ "$attempt" -lt 2 ]; do
    if ! /system/bin/umount -l "$DEFEX_ALIAS" 2>/dev/null; then
      echo "defex-exec: could not detach alias mount" >&2
      break
    fi
    attempt=$((attempt + 1))
    count=$(mount_count)
  done
  if [ "$count" -ne 0 ]; then
    echo "defex-exec: $count alias mount(s) remain in this namespace" >&2
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
if [ "$(mount_count)" -ne 1 ]; then
  echo "defex-exec: helper alias did not appear exactly once" >&2
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
