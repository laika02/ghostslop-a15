package io.github.rhythmcache.adb.pairing

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.Socket

/**
 * Host/client-side entry point for the ADB pairing protocol: connects to a
 * device that is advertising a pairing code (QR or 6-digit), and runs the
 * full SPAKE2 + TLS pairing exchange.
 */
object PairingClient {
    /**
     * Pairs with a device at [host]:[port] using [password] (the raw bytes
     * of the pairing code shown on-device). Returns [PairingResult] containing
     * the device's PeerInfo (expected type ADB_DEVICE_GUID) and peer X.509 certificate PEM.
     */
    suspend fun pair(
        host: String,
        port: Int,
        password: ByteArray,
        ourPeerInfo: PeerInfo,
        identity: PairingIdentity,
        connectTimeoutMs: Int = 10_000,
    ): Result<PairingResult> =
        withContext(Dispatchers.IO) {
            val socket = Socket()
            try {
                socket.connect(java.net.InetSocketAddress(host, port), connectTimeoutMs)
                socket.tcpNoDelay = true
            } catch (e: Exception) {
                runCatching { socket.close() }
                return@withContext Result.failure(e)
            }

            PairingConnection.run(socket, ConnectionRole.CLIENT, password, ourPeerInfo, identity)
        }
}
