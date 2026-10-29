package io.github.rhythmcache.adb

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okio.BufferedSink
import okio.BufferedSource
import okio.buffer
import okio.sink
import okio.source
import java.net.Socket

class TcpPacketTransport private constructor(
    private val socket: Socket,
    private val source: BufferedSource,
    private val sink: BufferedSink,
) : PacketTransport {
    companion object {
        suspend fun connect(
            host: String,
            port: Int = 5555,
        ): TcpPacketTransport =
            withContext(Dispatchers.IO) {
                val socket = Socket(host, port)
                socket.tcpNoDelay = true
                val source = socket.source().buffer()
                val sink = socket.sink().buffer()
                TcpPacketTransport(socket, source, sink)
            }
    }

    private val writeLock = Any()

    override fun send(pkt: AdbPacket) {
        synchronized(writeLock) {
            pkt.writeTo(sink)
        }
    }

    override fun recv(): AdbPacket = AdbPacket.readFrom(source)

    override fun close() {
        runCatching { source.close() }
        runCatching { sink.close() }
        runCatching { socket.close() }
    }
}
