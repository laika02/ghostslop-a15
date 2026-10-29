package io.github.rhythmcache.adb

import io.github.rhythmcache.adb.install.AdbInstall
import io.github.rhythmcache.adb.pairing.PairingClient
import io.github.rhythmcache.adb.pairing.PairingIdentity
import io.github.rhythmcache.adb.pairing.PairingResult
import io.github.rhythmcache.adb.pairing.PeerInfoBuilder
import io.github.rhythmcache.adb.pairing.buildPairingIdentity
import io.github.rhythmcache.adb.rescue.AdbRescue
import io.github.rhythmcache.adb.sideload.AdbSideload
import io.github.rhythmcache.adb.sync.AdbSync
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.Closeable

class AdbClient private constructor(
    private val connection: AdbConnection,
) : Closeable {
    val sync: AdbSync = AdbSync(connection)
    val forward: AdbForward = AdbForward(connection)
    val reverse: AdbReverse = AdbReverse(connection)
    val sideload: AdbSideload = AdbSideload(connection)
    val rescue: AdbRescue = AdbRescue(connection)
    val install: AdbInstall = AdbInstall(connection)

    val deviceMode: AdbDeviceMode get() = connection.deviceMode
    val bannerString: String get() = connection.bannerString

    companion object {
        /** Connect over Plain TCP (Port 5555 or custom TCP port). */
        suspend fun connectTcp(
            host: String,
            port: Int = 5555,
            keyProvider: AdbKeyProvider = MemoryKeyProvider,
            handshakeTimeoutMs: Long = 30_000,
        ): AdbClient {
            val transport = TcpPacketTransport.connect(host, port)
            val connection = AdbConnection.connect(transport, keyProvider, handshakeTimeoutMs)
            return AdbClient(connection)
        }

        /** Connect over Wireless Debugging TLS (Android 11+ TLS port). */
        suspend fun connectTls(
            host: String,
            port: Int,
            keyProvider: AdbKeyProvider = MemoryKeyProvider,
            identity: PairingIdentity? = null,
            handshakeTimeoutMs: Long = 30_000,
        ): AdbClient {
            val resolvedIdentity = identity ?: buildPairingIdentity(keyProvider)
            val transport = TlsPacketTransport.connect(host, port, resolvedIdentity)
            val connection = AdbConnection.connect(transport, keyProvider, handshakeTimeoutMs)
            return AdbClient(connection)
        }

        /** Pair with a device advertising a pairing code over Wireless Debugging TLS. */
        suspend fun pairTls(
            host: String,
            port: Int,
            pairingCode: String,
            keyProvider: AdbKeyProvider = MemoryKeyProvider,
            identity: PairingIdentity? = null,
            connectTimeoutMs: Int = 10_000,
        ): Result<PairingResult> {
            val resolvedIdentity = identity ?: buildPairingIdentity(keyProvider)
            val passwordBytes = pairingCode.toByteArray(Charsets.US_ASCII)
            val ourPeerInfo = PeerInfoBuilder.forOurKeyProvider(keyProvider)
            return PairingClient.pair(
                host = host,
                port = port,
                password = passwordBytes,
                ourPeerInfo = ourPeerInfo,
                identity = resolvedIdentity,
                connectTimeoutMs = connectTimeoutMs,
            )
        }

        /** Legacy alias for connectTcp */
        suspend fun connect(
            host: String,
            port: Int = 5555,
            keyProvider: AdbKeyProvider = MemoryKeyProvider,
            handshakeTimeoutMs: Long = 30_000,
        ): AdbClient = connectTcp(host, port, keyProvider, handshakeTimeoutMs)

        /** Connect using any custom PacketTransport instance. */
        suspend fun connect(
            transport: PacketTransport,
            keyProvider: AdbKeyProvider = MemoryKeyProvider,
            handshakeTimeoutMs: Long = 30_000,
        ): AdbClient {
            val connection = AdbConnection.connect(transport, keyProvider, handshakeTimeoutMs)
            return AdbClient(connection)
        }
    }

    /** Universal escape hatch for raw streams */
    suspend fun open(service: String): AdbStream = connection.open(service)

    /** Universal escape hatch for raw streams using type-safe endpoints. */
    suspend fun open(endpoint: AdbEndpoint): AdbStream = connection.open(endpoint.toSpec())

    /** Run a shell command to completion. */
    suspend fun shell(cmd: String): ShellResult {
        val stream = connection.open("shell,v2,raw:$cmd")
        return try {
            AdbShell.collectToResult(stream)
        } finally {
            stream.close()
        }
    }

    /** Stream shell chunks live as a Flow. Guarantees closing stream on completion or cancellation. */
    fun shellFlow(cmd: String): Flow<ShellChunk> =
        kotlinx.coroutines.flow.flow {
            val stream = connection.open("shell,v2,raw:$cmd")
            try {
                AdbShell.flow(stream).collect { emit(it) }
            } finally {
                stream.close()
            }
        }

    /**
     * Opens an interactive Shell v2 PTY session with terminal type and optional initial dimensions.
     * Passing non-positive values for [rows] or [cols] skips the initial dimension synchronization.
     */
    suspend fun openInteractiveShell(
        terminalType: String = "xterm-256color",
        rows: Int = 24,
        cols: Int = 80,
    ): AdbInteractiveSession {
        val service =
            if (terminalType.isNotBlank()) {
                "shell,v2,pty,TERM=$terminalType:"
            } else {
                "shell,v2,pty:"
            }
        val stream = connection.open(service)
        val session = AdbInteractiveSession(stream)
        if (rows > 0 && cols > 0) {
            session.resize(cols, rows)
        }
        return session
    }

    /** Restart adbd with root permissions (requires eng or userdebug build). */
    suspend fun root(timeoutMs: Long = 5000): String =
        withContext(Dispatchers.IO) {
            val stream = connection.open("root:")
            try {
                val result =
                    withTimeoutOrNull(timeoutMs) {
                        val bytes = stream.readToEnd()
                        String(bytes, Charsets.UTF_8).trim()
                    }
                when {
                    result == null -> "Timeout: Daemon failed to respond"
                    result.isEmpty() -> "No output returned by daemon"
                    else -> result
                }
            } catch (e: Exception) {
                "Error: ${e.message}"
            } finally {
                runCatching { stream.close() }
            }
        }

    /** Restart adbd without root permissions. */
    suspend fun unroot(timeoutMs: Long = 5000): String =
        withContext(Dispatchers.IO) {
            val stream = connection.open("unroot:")
            try {
                val result =
                    withTimeoutOrNull(timeoutMs) {
                        val bytes = stream.readToEnd()
                        String(bytes, Charsets.UTF_8).trim()
                    }
                when {
                    result == null -> "Timeout: Daemon failed to respond"
                    result.isEmpty() -> "No output returned by daemon"
                    else -> result
                }
            } catch (e: Exception) {
                "Error: ${e.message}"
            } finally {
                runCatching { stream.close() }
            }
        }

    /** Restart adbd listening on TCP on the specified port. */
    suspend fun tcpip(
        port: Int = 5555,
        timeoutMs: Long = 5000,
    ): String =
        withContext(Dispatchers.IO) {
            require(port in 1..65535) { "Invalid TCP port: $port" }
            val stream = connection.open("tcpip:$port")
            try {
                val result =
                    withTimeoutOrNull(timeoutMs) {
                        val bytes = stream.readToEnd()
                        String(bytes, Charsets.UTF_8).trim()
                    }
                when {
                    result == null -> "Timeout: Daemon failed to respond"
                    result.isEmpty() -> "No output returned by daemon"
                    else -> result
                }
            } catch (e: Exception) {
                "Error: ${e.message}"
            } finally {
                runCatching { stream.close() }
            }
        }

    val isClosed: Boolean get() = connection.isClosed

    override fun close() {
        forward.close()
        connection.close()
    }
}
