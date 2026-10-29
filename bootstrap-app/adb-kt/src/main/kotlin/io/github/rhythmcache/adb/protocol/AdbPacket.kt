package io.github.rhythmcache.adb

import okio.BufferedSink
import okio.BufferedSource
import java.io.EOFException

/**
 * Wire-format ADB packet: 24-byte header + payload.
 * [payload] may be a larger backing array; only [payloadOffset] until
 * [payloadOffset] + [payloadLength] is considered part of this packet.
 */
data class AdbPacket(
    val command: Int,
    val arg0: Int,
    val arg1: Int,
    val payload: ByteArray,
    val payloadOffset: Int = 0,
    val payloadLength: Int = payload.size,
) {
    companion object {
        fun checksum(
            data: ByteArray,
            offset: Int = 0,
            length: Int = data.size,
        ): Int {
            var acc = 0
            val end = offset + length
            for (i in offset until end) acc += (data[i].toInt() and 0xFF)
            return acc
        }

        /** Reads exactly one packet directly from an Okio BufferedSource. */
        fun readFrom(source: BufferedSource): AdbPacket {
            try {
                val command = source.readIntLe()
                val arg0 = source.readIntLe()
                val arg1 = source.readIntLe()
                val len = source.readIntLe()
                source.readIntLe() // checksum, unused on TCP path
                val magic = source.readIntLe()

                if ((command xor magic) != -1) {
                    throw AdbException.Protocol(
                        "Invalid ADB packet magic (command: 0x${command.toString(16)}, magic: 0x${magic.toString(16)})",
                    )
                }

                val payload =
                    if (len > 0) {
                        if (len > MAX_PAYLOAD * 4) {
                            throw AdbException.Protocol("ADB packet payload too large: $len bytes")
                        }
                        source.readByteArray(len.toLong())
                    } else {
                        ByteArray(0)
                    }

                return AdbPacket(command, arg0, arg1, payload)
            } catch (e: EOFException) {
                throw AdbException.Transport("EOF reached while reading ADB packet", e)
            } catch (e: AdbException) {
                throw e
            } catch (e: Exception) {
                throw AdbException.Transport("Failed to read ADB packet", e)
            }
        }
    }

    /** Writes packet header and payload directly into an Okio BufferedSink. */
    fun writeTo(sink: BufferedSink) {
        val chk = checksum(payload, payloadOffset, payloadLength)
        val magic = command xor -1

        sink.writeIntLe(command)
        sink.writeIntLe(arg0)
        sink.writeIntLe(arg1)
        sink.writeIntLe(payloadLength)
        sink.writeIntLe(chk)
        sink.writeIntLe(magic)
        if (payloadLength > 0) {
            sink.write(payload, payloadOffset, payloadLength)
        }
        sink.flush()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as AdbPacket
        if (command != other.command) return false
        if (arg0 != other.arg0) return false
        if (arg1 != other.arg1) return false
        if (payloadLength != other.payloadLength) return false
        for (i in 0 until payloadLength) {
            if (payload[payloadOffset + i] != other.payload[other.payloadOffset + i]) return false
        }
        return true
    }

    override fun hashCode(): Int {
        var result = command
        result = 31 * result + arg0
        result = 31 * result + arg1
        for (i in 0 until payloadLength) {
            result = 31 * result + payload[payloadOffset + i]
        }
        return result
    }
}
