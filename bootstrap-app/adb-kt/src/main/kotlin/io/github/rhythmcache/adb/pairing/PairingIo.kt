package io.github.rhythmcache.adb.pairing

import java.io.InputStream
import java.io.OutputStream

/**
 * Reads and writes PairingPacketHeader + payload over a raw InputStream/
 * OutputStream (TLS record boundaries don't align with logical frames, so
 * everything here loops until the exact byte count is satisfied).
 */
internal object PairingIo {
    fun writePacket(
        out: OutputStream,
        type: Int,
        payload: ByteArray,
    ) {
        val header = PairingPacketHeader.create(type, payload.size)
        out.write(header.encode())
        out.write(payload)
        out.flush()
    }

    /** Reads exactly one packet header + its payload. Throws PairingException on any failure. */
    fun readPacket(input: InputStream): Pair<PairingPacketHeader, ByteArray> {
        val headerBuf = readFully(input, PairingPacketHeader.SIZE)
        val header = PairingPacketHeader.parse(headerBuf)
        val payload = readFully(input, header.payloadSize)
        return header to payload
    }

    private fun readFully(
        input: InputStream,
        size: Int,
    ): ByteArray {
        val buf = ByteArray(size)
        var offset = 0
        while (offset < size) {
            val n = input.read(buf, offset, size - offset)
            if (n < 0) {
                throw PairingException("EOF while reading $size bytes (got $offset)")
            }
            offset += n
        }
        return buf
    }
}
