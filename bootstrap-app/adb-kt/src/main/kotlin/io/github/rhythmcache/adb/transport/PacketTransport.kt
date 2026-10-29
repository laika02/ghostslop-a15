package io.github.rhythmcache.adb

import java.io.Closeable

interface PacketTransport : Closeable {
    fun send(pkt: AdbPacket)

    fun recv(): AdbPacket

    override fun close()
}
