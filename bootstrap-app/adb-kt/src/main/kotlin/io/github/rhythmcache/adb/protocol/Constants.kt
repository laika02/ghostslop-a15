package io.github.rhythmcache.adb

object AdbCmd {
    const val SYNC: Int = 0x434e5953
    const val CNXN: Int = 0x4e584e43
    const val AUTH: Int = 0x48545541
    const val OPEN: Int = 0x4e45504f
    const val OKAY: Int = 0x59414b4f
    const val CLSE: Int = 0x45534c43
    const val WRTE: Int = 0x45545257
    const val STLS: Int = 0x534c5453 // TLS(version, "") -- wireless debugging cleartext upgrade
}

object AdbAuthType {
    const val TOKEN: Int = 1
    const val SIGNATURE: Int = 2
    const val RSAPUBLICKEY: Int = 3
}

const val ADB_VERSION: Int = 0x01000001
const val MAX_PAYLOAD: Int = 1024 * 1024

internal val HOST_FEATURES_BYTES: ByteArray =
    (
        "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir," +
            "apex,abb,fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app," +
            "sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd," +
            "sendrecv_v2_dry_run_send,openscreen_mdns\u0000"
    ).toByteArray(Charsets.US_ASCII)
