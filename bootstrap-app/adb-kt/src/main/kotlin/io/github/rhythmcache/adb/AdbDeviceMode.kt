package io.github.rhythmcache.adb

enum class AdbDeviceMode {
    DEVICE,
    RECOVERY,
    SIDELOAD,
    RESCUE,
    HOST,
    UNKNOWN,
    ;

    companion object {
        fun parse(type: String): AdbDeviceMode =
            when (type.lowercase()) {
                "device" -> DEVICE
                "recovery" -> RECOVERY
                "sideload" -> SIDELOAD
                "rescue" -> RESCUE
                "host" -> HOST
                else -> UNKNOWN
            }
    }
}
