#!/system/bin/sh
# Source in the g4sh /system/bin/sh session to enable `g4run COMMAND`.
g4run() {
  /system/bin/sh /data/local/tmp/a/g4run "$@"
}
