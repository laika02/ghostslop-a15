package io.github.rhythmcache.adb.pairing

import java.net.Socket
import java.security.KeyPair

enum class ConnectionRole { CLIENT, SERVER }

data class PairingIdentity(
    val keyPair: KeyPair,
    val certPem: String,
    val privateKeyPem: String,
)

data class PairingResult(
    val peerInfo: PeerInfo,
    val peerCertPem: String?,
)

/**
 * Runs the full ADB pairing exchange over an already-connected raw [socket]:
 * TLS handshake (accept-any-cert) -> export keying material -> append to
 * password -> SPAKE2 exchange -> AES-GCM-encrypted PeerInfo exchange.
 *
 * Blocking call; run it off the main thread / in a coroutine with
 * Dispatchers.IO. Closes [socket] on both success and failure.
 */
object PairingConnection {
    private const val EXPORTED_KEY_SIZE = 64

    fun run(
        socket: Socket,
        role: ConnectionRole,
        password: ByteArray,
        ourPeerInfo: PeerInfo,
        identity: PairingIdentity,
    ): Result<PairingResult> {
        return try {
            val tls =
                when (role) {
                    ConnectionRole.CLIENT ->
                        PairingTlsSocket.connectAsClient(socket, identity.certPem, identity.privateKeyPem)
                    ConnectionRole.SERVER ->
                        PairingTlsSocket.connectAsServer(socket, identity.certPem, identity.privateKeyPem)
                }

            try {
                val exported = tls.exportKeyingMaterial(EXPORTED_KEY_SIZE)
                val combinedPassword = password + exported

                val authRole =
                    when (role) {
                        ConnectionRole.CLIENT -> PairingRole.CLIENT
                        ConnectionRole.SERVER -> PairingRole.SERVER
                    }
                val auth = PairingAuthCtx(authRole, combinedPassword)

                val input = tls.inputStream()
                val output = tls.outputStream()

                // Exchange SPAKE2 messages
                PairingIo.writePacket(output, PairingPacketHeader.TYPE_SPAKE2_MSG, auth.ourMsg)

                val (spakeHeader, theirSpakeMsg) = PairingIo.readPacket(input)
                if (spakeHeader.type != PairingPacketHeader.TYPE_SPAKE2_MSG) {
                    return Result.failure(PairingException("Expected SPAKE2_MSG, got type=${spakeHeader.type}"))
                }

                if (!auth.initCipher(theirSpakeMsg)) {
                    return Result.failure(PairingException("Failed to initialize pairing cipher"))
                }

                // Exchange PeerInfo, encrypted
                val encryptedOurs =
                    auth.encrypt(ourPeerInfo.encode())
                        ?: return Result.failure(PairingException("Failed to encrypt our PeerInfo"))
                PairingIo.writePacket(output, PairingPacketHeader.TYPE_PEER_INFO, encryptedOurs)

                val (peerInfoHeader, encryptedTheirs) = PairingIo.readPacket(input)
                if (peerInfoHeader.type != PairingPacketHeader.TYPE_PEER_INFO) {
                    return Result.failure(PairingException("Expected PEER_INFO, got type=${peerInfoHeader.type}"))
                }

                val decrypted =
                    auth.decrypt(encryptedTheirs)
                        ?: return Result.failure(
                            PairingException("Failed to decrypt peer's PeerInfo -- likely wrong pairing code"),
                        )

                if (decrypted.size != PEER_INFO_SIZE) {
                    return Result.failure(
                        PairingException("Decrypted PeerInfo has wrong size: ${decrypted.size}"),
                    )
                }

                Result.success(PairingResult(PeerInfo.decode(decrypted), tls.peerCertPem))
            } finally {
                tls.close()
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
