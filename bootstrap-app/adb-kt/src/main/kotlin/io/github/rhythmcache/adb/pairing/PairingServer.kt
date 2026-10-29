package io.github.rhythmcache.adb.pairing

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

/**
 * Device/server-side entry point: listens for incoming pairing connections
 * (mirrors the AOSP PairingConnectionCtx server role -- one server instance
 * services exactly one client connection per pairing attempt, though this
 * class handles accepting the underlying TCP connection which
 * PairingConnectionCtx itself doesn't do).
 *
 * Enforces the same limits as AOSP's pairing/internal/constants.h:
 * kMaxConnections (10) concurrent connections, kMaxPairingAttempts (20)
 * total attempts before refusing further connections -- this exists
 * specifically to blunt brute-force attempts against the pairing code.
 */
class PairingServer(
    private val port: Int,
    private val password: ByteArray,
    private val ourPeerInfo: PeerInfo,
    private val identity: PairingIdentity,
    private val onResult: suspend (Result<PairingResult>) -> Unit,
) {
    companion object {
        const val MAX_CONNECTIONS = 10
        const val MAX_PAIRING_ATTEMPTS = 20
    }

    private val activeConnections = AtomicInteger(0)
    private val totalAttempts = AtomicInteger(0)
    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null

    /** Starts listening. Returns the actual bound port (useful if [port] was 0). */
    fun start(scope: CoroutineScope): Int {
        val ss = ServerSocket(port)
        serverSocket = ss

        acceptJob =
            scope.launch(Dispatchers.IO) {
                while (!ss.isClosed) {
                    val socket =
                        try {
                            ss.accept()
                        } catch (e: Exception) {
                            break // socket closed, stop() was called
                        }

                    if (totalAttempts.incrementAndGet() > MAX_PAIRING_ATTEMPTS) {
                        runCatching { socket.close() }
                        continue
                    }

                    if (activeConnections.incrementAndGet() > MAX_CONNECTIONS) {
                        activeConnections.decrementAndGet()
                        runCatching { socket.close() }
                        continue
                    }

                    launch(Dispatchers.IO) {
                        handleConnection(socket)
                        activeConnections.decrementAndGet()
                    }
                }
            }

        return ss.localPort
    }

    private suspend fun handleConnection(socket: Socket) {
        val result = PairingConnection.run(socket, ConnectionRole.SERVER, password, ourPeerInfo, identity)
        onResult(result)
    }

    fun stop() {
        acceptJob?.cancel()
        runCatching { serverSocket?.close() }
    }
}
