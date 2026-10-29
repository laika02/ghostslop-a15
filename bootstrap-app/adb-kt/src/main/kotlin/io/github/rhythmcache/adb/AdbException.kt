package io.github.rhythmcache.adb

sealed class AdbException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    class Io(
        message: String,
        cause: Throwable? = null,
    ) : AdbException(message, cause)

    class Transport(
        message: String,
        cause: Throwable? = null,
    ) : AdbException(message, cause)

    class Protocol(
        message: String,
    ) : AdbException(message)

    class Authentication(
        message: String,
    ) : AdbException(message)

    class StreamClosed(
        message: String = "ADB stream is closed",
    ) : AdbException(message)

    class RemoteFailure(
        message: String,
    ) : AdbException(message)

    class Timeout(
        message: String = "ADB operation timed out",
    ) : AdbException(message)

    class ServerFail(
        message: String,
    ) : AdbException(message)

    class NotPaired(
        message: String = "Device rejected this key - pair it first.",
        cause: Throwable? = null,
    ) : AdbException(message, cause)
}
