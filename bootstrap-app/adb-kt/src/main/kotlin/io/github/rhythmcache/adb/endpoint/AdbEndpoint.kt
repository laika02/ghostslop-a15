package io.github.rhythmcache.adb

sealed interface AdbEndpoint {
    fun toSpec(): String

    data class Tcp(
        val port: Int,
    ) : AdbEndpoint {
        override fun toSpec(): String = "tcp:$port"
    }

    data class LocalAbstract(
        val name: String,
    ) : AdbEndpoint {
        override fun toSpec(): String = "localabstract:$name"
    }

    data class LocalReserved(
        val name: String,
    ) : AdbEndpoint {
        override fun toSpec(): String = "localreserved:$name"
    }

    data class LocalFilesystem(
        val name: String,
    ) : AdbEndpoint {
        override fun toSpec(): String = "localfilesystem:$name"
    }

    data class Dev(
        val name: String,
    ) : AdbEndpoint {
        override fun toSpec(): String = "dev:$name"
    }

    data class Jdwp(
        val pid: Int,
    ) : AdbEndpoint {
        override fun toSpec(): String = "jdwp:$pid"
    }

    data class Raw(
        val spec: String,
    ) : AdbEndpoint {
        override fun toSpec(): String = spec
    }
}
