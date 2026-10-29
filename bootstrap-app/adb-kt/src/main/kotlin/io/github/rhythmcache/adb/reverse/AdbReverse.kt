package io.github.rhythmcache.adb

class AdbReverse internal constructor(
    private val connection: AdbConnection,
) {
    suspend fun add(
        local: String,
        remote: String,
    ) {
        val stream = connection.open("reverse:forward:$local;$remote")
        val resp =
            try {
                stream.readToEnd().toString(Charsets.UTF_8)
            } finally {
                stream.close()
            }
        if (resp.startsWith("FAIL")) {
            throw AdbException.RemoteFailure("Reverse failed: $resp")
        }
    }

    suspend fun add(
        local: AdbEndpoint,
        remote: AdbEndpoint,
    ) {
        add(local.toSpec(), remote.toSpec())
    }

    suspend fun remove(remote: String) {
        val stream = connection.open("reverse:killforward:$remote")
        stream.close()
    }

    suspend fun remove(remote: AdbEndpoint) {
        remove(remote.toSpec())
    }

    suspend fun removeAll() {
        val stream = connection.open("reverse:killforward-all")
        stream.close()
    }
}
