package io.github.rhythmcache.adb

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.io.Closeable
import java.security.KeyPair
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.atomic.AtomicInteger

class AdbConnection private constructor(
    private val openChannel: Channel<StreamReg>,
    private val sharedCmdChannel: Channel<StreamCmd>,
    private val scope: CoroutineScope,
    val deviceMode: AdbDeviceMode = AdbDeviceMode.UNKNOWN,
    val bannerString: String = "",
    val maxPayload: Int = 4096,
) : Closeable {
    internal data class StreamReg(
        val localId: Int,
        val service: String,
        val shared: StreamShared,
    )

    companion object {
        private val streamCounter = AtomicInteger(1)

        private fun nextLocalId(): Int {
            var current: Int
            var next: Int
            do {
                current = streamCounter.get()
                next = if (current >= Int.MAX_VALUE || current < 1) 1 else current + 1
            } while (!streamCounter.compareAndSet(current, next))
            return current
        }

        suspend fun connect(
            transport: PacketTransport,
            keyProvider: AdbKeyProvider,
            handshakeTimeoutMs: Long = 30_000,
            skipInitialCnxn: Boolean = (transport is TlsPacketTransport),
        ): AdbConnection {
            val sharedCmdChannel = Channel<StreamCmd>(capacity = 64)
            val regChannel = Channel<StreamReg>(capacity = 16)
            val streams = HashMap<Int, StreamShared>()
            val streamsMutex = Mutex()
            val handshakeResult = CompletableDeferred<Unit>()
            var detectedMode = AdbDeviceMode.UNKNOWN
            var detectedBanner = ""
            var detectedMaxPayload = 4096

            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

            scope.launch {
                try {
                    ioLoop(
                        transport,
                        streams,
                        streamsMutex,
                        sharedCmdChannel,
                        regChannel,
                        keyProvider,
                        handshakeResult,
                        skipInitialCnxn,
                    ) { mode, banner, payloadSize ->
                        detectedMode = mode
                        detectedBanner = banner
                        detectedMaxPayload = payloadSize
                    }
                } finally {
                    scope.cancel()
                }
            }

            withTimeoutOrNull(handshakeTimeoutMs) {
                handshakeResult.await()
            } ?: run {
                scope.cancel()
                throw AdbException.Timeout("ADB CNXN/AUTH handshake timed out")
            }

            return AdbConnection(
                openChannel = regChannel,
                sharedCmdChannel = sharedCmdChannel,
                scope = scope,
                deviceMode = detectedMode,
                bannerString = detectedBanner,
                maxPayload = detectedMaxPayload,
            )
        }

        suspend fun connect(
            transport: PacketTransport,
            keyPair: KeyPair,
            handshakeTimeoutMs: Long = 30_000,
            skipInitialCnxn: Boolean = (transport is TlsPacketTransport),
        ): AdbConnection =
            connect(
                transport,
                object : AdbKeyProvider {
                    override suspend fun getKeyPair(): KeyPair = keyPair
                },
                handshakeTimeoutMs,
                skipInitialCnxn,
            )

        private suspend fun ioLoop(
            transport: PacketTransport,
            streams: HashMap<Int, StreamShared>,
            streamsMutex: Mutex,
            cmdChannel: Channel<StreamCmd>,
            regChannel: Channel<StreamReg>,
            keyProvider: AdbKeyProvider,
            handshakeResult: CompletableDeferred<Unit>,
            skipInitialCnxn: Boolean = false,
            onBannerReceived: (AdbDeviceMode, String, Int) -> Unit,
        ) = coroutineScope {
            // On a TLS transport, the plaintext CNXN was already sent in
            // TlsPacketTransport.connect() to trigger the STLS upgrade flow.
            // Sending another encrypted CNXN would cause the device to call
            // handle_offline() + send_tls_request() again, tearing down the
            // connection. The device auto-sends its encrypted CNXN after TLS.
            if (!skipInitialCnxn) {
                try {
                    transport.send(AdbPacket(AdbCmd.CNXN, ADB_VERSION, MAX_PAYLOAD, HOST_FEATURES_BYTES))
                } catch (e: Exception) {
                    handshakeResult.completeExceptionally(e)
                    return@coroutineScope
                }
            }

            var triedSignature = false

            val readerJob =
                launch {
                    while (isActive) {
                        val pkt =
                            try {
                                transport.recv()
                            } catch (e: AdbException.Timeout) {
                                continue
                            } catch (e: Exception) {
                                broadcastError(streams, streamsMutex, e)
                                if (!handshakeResult.isCompleted) handshakeResult.completeExceptionally(e)
                                break
                            }
                        try {
                            dispatch(
                                pkt,
                                transport,
                                streams,
                                streamsMutex,
                                keyProvider,
                                triedSignature,
                                handshakeResult,
                                onBannerReceived,
                            ) { newVal ->
                                triedSignature = newVal
                            }
                        } catch (e: Exception) {
                            broadcastError(streams, streamsMutex, e)
                            if (!handshakeResult.isCompleted) handshakeResult.completeExceptionally(e)
                            break
                        }
                    }
                }

            val regJob =
                launch {
                    for (reg in regChannel) {
                        val payload = (reg.service + "\u0000").toByteArray(Charsets.UTF_8)
                        streamsMutex.withLock { streams[reg.localId] = reg.shared }
                        try {
                            transport.send(AdbPacket(AdbCmd.OPEN, reg.localId, 0, payload))
                        } catch (e: Exception) {
                            broadcastError(streams, streamsMutex, e)
                            break
                        }
                    }
                }

            val cmdJob =
                launch {
                    for (cmd in cmdChannel) {
                        val pkt =
                            when (cmd) {
                                is StreamCmd.Write -> AdbPacket(AdbCmd.WRTE, cmd.localId, cmd.remoteId, cmd.data, cmd.offset, cmd.length)
                                is StreamCmd.Close -> {
                                    streamsMutex.withLock { streams.remove(cmd.localId) }
                                    AdbPacket(AdbCmd.CLSE, cmd.localId, cmd.remoteId, ByteArray(0))
                                }
                                is StreamCmd.AbortOpen -> {
                                    streamsMutex.withLock { streams.remove(cmd.localId) }
                                    null
                                }
                            }
                        if (pkt != null) {
                            try {
                                transport.send(pkt)
                            } catch (e: Exception) {
                                broadcastError(streams, streamsMutex, e)
                                break
                            }
                        }
                    }
                }

            readerJob.join()
            regJob.cancel()
            cmdJob.cancel()
            streamsMutex.withLock { streams.clear() }
            transport.close()
        }

        private suspend fun dispatch(
            pkt: AdbPacket,
            transport: PacketTransport,
            streams: HashMap<Int, StreamShared>,
            streamsMutex: Mutex,
            keyProvider: AdbKeyProvider,
            triedSignature: Boolean,
            handshakeResult: CompletableDeferred<Unit>,
            onBannerReceived: (AdbDeviceMode, String, Int) -> Unit,
            setTriedSignature: (Boolean) -> Unit,
        ) {
            when (pkt.command) {
                AdbCmd.AUTH ->
                    if (pkt.arg0 == AdbAuthType.TOKEN) {
                        val keyPair = keyProvider.getKeyPair()
                        if (!triedSignature) {
                            setTriedSignature(true)
                            val sig = AdbAuth.signToken(keyPair.private, pkt.payload)
                            transport.send(AdbPacket(AdbCmd.AUTH, AdbAuthType.SIGNATURE, 0, sig))
                        } else {
                            val pubKeyBytes =
                                keyProvider.getAdbPublicKeyBytes()
                                    ?: AdbAuth.encodePublicKeyAdb(keyPair.public as RSAPublicKey)
                            transport.send(AdbPacket(AdbCmd.AUTH, AdbAuthType.RSAPUBLICKEY, 0, pubKeyBytes))
                        }
                    }

                AdbCmd.CNXN -> {
                    val banner = String(pkt.payload, Charsets.UTF_8)
                    val modePrefix = banner.substringBefore("::", "")
                    val deviceMaxPayload = if (pkt.arg1 > 0) minOf(pkt.arg1, MAX_PAYLOAD) else 4096
                    onBannerReceived(AdbDeviceMode.parse(modePrefix), banner, deviceMaxPayload)
                    if (!handshakeResult.isCompleted) handshakeResult.complete(Unit)
                }

                AdbCmd.OKAY -> {
                    val localId = pkt.arg1
                    val remoteId = pkt.arg0
                    streamsMutex.withLock {
                        streams[localId]?.let { entry ->
                            if (entry.remoteId == null) {
                                entry.remoteId = remoteId
                                entry.openSignal?.complete(remoteId)
                                entry.openSignal = null
                            }
                            try {
                                entry.flowSemaphore.release()
                            } catch (_: IllegalStateException) {
                                // Ignore duplicate OKAY permit release for abandoned/closed streams
                            }
                        }
                    }
                }

                AdbCmd.WRTE -> {
                    val localId = pkt.arg1
                    val remoteId = pkt.arg0
                    streamsMutex.withLock {
                        streams[localId]?.dataChannel?.trySend(Result.success(pkt.payload))
                    }
                    transport.send(AdbPacket(AdbCmd.OKAY, localId, remoteId, ByteArray(0)))
                }

                AdbCmd.CLSE -> {
                    val localId = pkt.arg1
                    streamsMutex.withLock {
                        val entry = streams.remove(localId) ?: return@withLock
                        val openSignal = entry.openSignal
                        entry.openSignal = null
                        if (openSignal != null) {
                            // Stream was never opened umm adbd rejected OPEN
                            openSignal.completeExceptionally(
                                AdbException.RemoteFailure("Remote closed stream before opening"),
                            )
                        } else {
                            // Stream was open and is now closing normally
                            entry.dataChannel.close()
                        }
                    }
                }
            }
        }

        private suspend fun broadcastError(
            streams: HashMap<Int, StreamShared>,
            streamsMutex: Mutex,
            e: Exception,
        ) {
            streamsMutex.withLock {
                for (entry in streams.values) {
                    entry.dataChannel.trySend(Result.failure(e))
                    entry.openSignal?.completeExceptionally(e)
                }
            }
        }
    }

    /** Opens a new logical stream for the given ADB service string. */
    suspend fun open(
        service: String,
        openTimeoutMs: Long = 10_000,
    ): AdbStream {
        val localId = nextLocalId()
        val shared = StreamShared(maxPayload = maxPayload)

        openChannel.send(StreamReg(localId, service, shared))

        val remoteId =
            withTimeoutOrNull(openTimeoutMs) {
                shared.openSignal!!.await()
            } ?: run {
                sharedCmdChannel.trySend(StreamCmd.AbortOpen(localId))
                throw AdbException.Timeout("Failed to open stream for '$service': timeout")
            }

        return AdbStream(localId, remoteId, shared.dataChannel, sharedCmdChannel, shared.flowSemaphore, maxPayload)
    }

    suspend fun open(
        endpoint: AdbEndpoint,
        openTimeoutMs: Long = 10_000,
    ): AdbStream = open(endpoint.toSpec(), openTimeoutMs)

    suspend fun openShell(cmd: String): AdbStream = open("shell:$cmd")

    val isClosed: Boolean get() = !scope.isActive

    override fun close() {
        scope.cancel()
    }
}
