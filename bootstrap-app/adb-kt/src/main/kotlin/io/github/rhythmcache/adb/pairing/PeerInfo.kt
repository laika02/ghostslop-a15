package io.github.rhythmcache.adb.pairing

import java.nio.ByteBuffer
import java.nio.ByteOrder

const val PEER_INFO_SIZE = 8192

object PeerInfoType {
    const val ADB_RSA_PUB_KEY: Int = 0
    const val ADB_DEVICE_GUID: Int = 1
}

/**
 * Port of the C struct:
 *   struct PeerInfo {
 *       uint8_t type;
 *       uint8_t data[kMaxPeerInfoSize - 1];
 *   } __attribute__((packed));
 * Fixed 8192-byte wire representation: 1 byte type + 8191 bytes data,
 * zero-padded. [data] passed in may be shorter than 8191 bytes; it will be
 * padded with zeros. It must not exceed 8191 bytes.
 */
class PeerInfo(
    val type: Int,
    val data: ByteArray,
) {
    init {
        require(data.size <= PEER_INFO_SIZE - 1) {
            "PeerInfo data too large: ${data.size} > ${PEER_INFO_SIZE - 1}"
        }
    }

    /** Serializes to the fixed 8192-byte wire format. */
    fun encode(): ByteArray {
        val out = ByteArray(PEER_INFO_SIZE)
        out[0] = type.toByte()
        System.arraycopy(data, 0, out, 1, data.size)
        return out
    }

    companion object {
        /**
         * Parses a fixed 8192-byte buffer into a PeerInfo. [data] in the
         * result retains trailing zero padding exactly as sent — callers
         * that expect a NUL-terminated string (e.g. device GUID) should trim
         * at the first zero byte themselves, since the C side reads it via
         * reinterpret_cast<const char*> which stops at NUL.
         */
        fun decode(buf: ByteArray): PeerInfo {
            require(buf.size == PEER_INFO_SIZE) {
                "PeerInfo buffer must be exactly $PEER_INFO_SIZE bytes, got ${buf.size}"
            }
            val type = buf[0].toInt() and 0xFF
            val data = buf.copyOfRange(1, buf.size)
            return PeerInfo(type, data)
        }

        /** Extracts a NUL-terminated ASCII/UTF-8 string from a PeerInfo's data field. */
        fun stringFromData(data: ByteArray): String {
            val nul = data.indexOf(0).let { if (it == -1) data.size else it }
            return String(data, 0, nul, Charsets.UTF_8)
        }
    }
}

/**
 * Port of PairingPacketHeader:
 *   uint8_t version; uint8_t type; uint32_t payload (network/big-endian);
 * 6 bytes total, packed.
 */
data class PairingPacketHeader(
    val version: Int,
    val type: Int,
    val payloadSize: Int,
) {
    companion object {
        const val SIZE = 6
        const val CURRENT_VERSION = 1
        const val MIN_SUPPORTED_VERSION = 1
        const val MAX_SUPPORTED_VERSION = 1

        const val TYPE_SPAKE2_MSG = 0
        const val TYPE_PEER_INFO = 1

        val MAX_PAYLOAD_SIZE = PEER_INFO_SIZE * 2

        fun create(
            type: Int,
            payloadSize: Int,
        ): PairingPacketHeader = PairingPacketHeader(CURRENT_VERSION, type, payloadSize)

        /** Parses and validates a 6-byte header buffer. Throws on any invalid field. */
        fun parse(buf: ByteArray): PairingPacketHeader {
            require(buf.size == SIZE) { "Header must be exactly $SIZE bytes" }

            val version = buf[0].toInt() and 0xFF
            if (version < MIN_SUPPORTED_VERSION || version > MAX_SUPPORTED_VERSION) {
                throw PairingException("PairingPacketHeader version mismatch (got $version)")
            }

            val type = buf[1].toInt() and 0xFF
            if (type != TYPE_SPAKE2_MSG && type != TYPE_PEER_INFO) {
                throw PairingException("Unknown PairingPacket type=$type")
            }

            val payload =
                ByteBuffer.wrap(buf, 2, 4).order(ByteOrder.BIG_ENDIAN).int

            if (payload == 0 || payload.toLong() > MAX_PAYLOAD_SIZE) {
                throw PairingException("header payload not within a safe size (size=$payload)")
            }

            return PairingPacketHeader(version, type, payload)
        }
    }

    /** Serializes to the 6-byte wire format, payload size as big-endian (network order). */
    fun encode(): ByteArray {
        val buf = ByteArray(SIZE)
        buf[0] = version.toByte()
        buf[1] = type.toByte()
        ByteBuffer.wrap(buf, 2, 4).order(ByteOrder.BIG_ENDIAN).putInt(payloadSize)
        return buf
    }
}

private fun ByteArray.indexOf(b: Byte): Int {
    for (i in indices) if (this[i] == b) return i
    return -1
}

class PairingException(
    message: String,
) : Exception(message)
