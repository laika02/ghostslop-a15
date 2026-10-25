# This file is sourced only by g4run's root fish instance.
# Wrap Termux executables so ordinary fish commands still use the DEFEX alias.

set -l termux_bin /data/data/com.termux/files/usr/bin
set -l runner /data/local/tmp/a/g4run
set -l builtin_names (builtin -n)
set -l command_names
set -l command_paths

for executable in $termux_bin/*
    if not test -x "$executable"; or test -d "$executable"
        continue
    end

    set -l name (string split -r -m 1 / "$executable")[-1]
    if not string match -rq '^[A-Za-z_][A-Za-z0-9_-]*$' -- "$name"
        continue
    end
    # Keep fish builtins, but replace default fish functions such as `ls`:
    # those often call the Termux executable directly and bypass g4run.
    if contains -- "$name" $builtin_names
        continue
    end

    set -a command_names "$name"
    set -a command_paths "$executable"
end

set -l index 1
while test $index -le (count $command_names)
    set -l name $command_names[$index]
    set -l executable $command_paths[$index]
    set -l escaped_runner (string escape -- "$runner")
    set -l escaped_executable (string escape -- "$executable")
    eval "function $name; /system/bin/sh $escaped_runner $escaped_executable \$argv; end"
    set index (math $index + 1)
end

function g4run
    /system/bin/sh /data/local/tmp/a/g4run $argv
end
