#!/system/bin/sh
# Run a selected executable with the temporary DEFEX pathname launcher.
# Invoke from the live g4sh root shell with:
#   /system/bin/sh /data/local/tmp/a/g4run COMMAND [ARG ...]

TERMUX_PREFIX=/data/data/com.termux/files/usr
TERMUX_HOME=/data/data/com.termux/files/home
DEFEX_RUNNER=/data/local/tmp/a/defex-exec.sh
FISH_INIT=/data/local/tmp/a/g4run-fish-init.fish

usage() {
  echo "usage: g4run COMMAND [ARG ...]" >&2
  echo "       g4run /absolute/path/to/binary [ARG ...]" >&2
  echo "       g4run --self-test" >&2
}

if [ "$#" -eq 0 ]; then
  usage
  exit 2
fi
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
  usage
  exit 0
fi
if [ ! -x "$DEFEX_RUNNER" ]; then
  echo "g4run: missing launcher $DEFEX_RUNNER" >&2
  exit 1
fi
if [ "$1" = "--self-test" ]; then
  if [ "$#" -ne 1 ]; then
    usage
    exit 2
  fi
  shift
  exec /system/bin/sh "$DEFEX_RUNNER" --self-test
fi

command_name=$1
shift
if [ "${command_name#*/}" != "$command_name" ]; then
  target=$command_name
else
  target=
  if [ -x "$TERMUX_PREFIX/bin/$command_name" ] &&
     [ ! -d "$TERMUX_PREFIX/bin/$command_name" ]; then
    target=$TERMUX_PREFIX/bin/$command_name
  else
    old_ifs=$IFS
    IFS=:
    for dir in ${PATH:-/system/bin:/system/xbin}; do
      [ -n "$dir" ] || dir=.
      candidate=$dir/$command_name
      if [ -x "$candidate" ] && [ ! -d "$candidate" ]; then
        target=$candidate
        break
      fi
    done
    IFS=$old_ifs
  fi
fi

if [ -z "$target" ] || [ ! -f "$target" ] || [ ! -x "$target" ]; then
  echo "g4run: executable not found: $command_name" >&2
  exit 127
fi

case "$target" in
  "$TERMUX_PREFIX"/*)
    if [ -z "${HOME:-}" ] || [ "$HOME" = "/" ]; then
      HOME=$TERMUX_HOME
    fi
    PREFIX=$TERMUX_PREFIX
    if [ -z "${TERM:-}" ] || [ "$TERM" = "dumb" ]; then
      TERM=xterm-256color
    fi
    TERMINFO=${TERMINFO:-$TERMUX_PREFIX/share/terminfo}
    PATH=$TERMUX_PREFIX/bin:/system/bin:/system/xbin${PATH:+:$PATH}
    export HOME PREFIX TERM TERMINFO PATH
    ;;
esac

if [ "$target" = "$TERMUX_PREFIX/bin/fish" ]; then
  if [ ! -r "$FISH_INIT" ]; then
    echo "g4run: missing fish command wrappers $FISH_INIT" >&2
    exit 1
  fi
  set -- "$target" --no-config --init-command "source $FISH_INIT" "$@"
  target=$1
  shift
fi

exec /system/bin/sh "$DEFEX_RUNNER" "$target" "$@"
