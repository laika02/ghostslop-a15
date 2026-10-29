package io.github.rhythmcache.adb

import io.github.rhythmcache.adb.crypto.CryptoProviders
import io.github.rhythmcache.adb.crypto.X509Generator
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSAPrivateKey as Asn1RsaPrivateKey
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

object AdbAuth {
    /** Generate 2048-bit RSA keypair using BouncyCastle if available, falling back to default provider. */
    fun generateKey(): KeyPair {
        val kpg =
            try {
                CryptoProviders.rsaKeyPairGenerator()
            } catch (_: Exception) {
                KeyPairGenerator.getInstance("RSA")
            }
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }

    /** Returns a BouncyCastle-backed RSA [KeyFactory]. */
    fun getKeyFactory(): KeyFactory = CryptoProviders.rsaKeyFactory()

    /**
     * Parses an RSA private key from arbitrary raw bytes (PEM PKCS#1/PKCS#8,
     * DER PKCS#1, or DER PKCS#8). Uses BouncyCastle so the resulting key always
     * implements [RSAPrivateCrtKey] on all Android versions.
     *
     * Returns null on any parse failure; does not throw.
     */
    fun parsePrivateKey(rawBytes: ByteArray): RSAPrivateCrtKey? {
        return try {
            val text =
                try {
                    String(rawBytes, Charsets.US_ASCII)
                } catch (_: Exception) {
                    ""
                }

            if (text.contains("-----BEGIN")) {
                val cleanBase64 =
                    text
                        .lines()
                        .filter { !it.startsWith("-----") }
                        .joinToString("")
                        .replace("\\s".toRegex(), "")
                val der = Base64.getDecoder().decode(cleanBase64)

                if (text.contains("RSA PRIVATE KEY") || isPkcs1Der(der)) {
                    parsePkcs1PrivateKey(der) ?: parsePkcs8PrivateKey(der)
                } else {
                    parsePkcs8PrivateKey(der) ?: parsePkcs1PrivateKey(der)
                }
            } else if (isPkcs1Der(rawBytes)) {
                parsePkcs1PrivateKey(rawBytes) ?: parsePkcs8PrivateKey(rawBytes)
            } else {
                parsePkcs8PrivateKey(rawBytes) ?: parsePkcs1PrivateKey(rawBytes)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun parsePkcs8PrivateKey(der: ByteArray): RSAPrivateCrtKey? {
        val spec = PKCS8EncodedKeySpec(der)

        // 1. Try BouncyCastle KeyFactory with PKCS8EncodedKeySpec
        try {
            val kf = CryptoProviders.rsaKeyFactory()
            val key = kf.generatePrivate(spec) as? RSAPrivateCrtKey
            if (key != null) return key
        } catch (_: Exception) {
        }

        // 2. Try parsing PKCS#8 ASN.1 directly to extract RSA CRT parameters
        try {
            val pki = PrivateKeyInfo.getInstance(der)
            val rsa = Asn1RsaPrivateKey.getInstance(pki.parsePrivateKey())
            val crtSpec =
                RSAPrivateCrtKeySpec(
                    rsa.modulus,
                    rsa.publicExponent,
                    rsa.privateExponent,
                    rsa.prime1,
                    rsa.prime2,
                    rsa.exponent1,
                    rsa.exponent2,
                    rsa.coefficient,
                )
            val key =
                try {
                    CryptoProviders.rsaKeyFactory().generatePrivate(crtSpec) as? RSAPrivateCrtKey
                } catch (_: Exception) {
                    null
                } ?: try {
                    KeyFactory.getInstance("RSA").generatePrivate(crtSpec) as? RSAPrivateCrtKey
                } catch (_: Exception) {
                    null
                }
            if (key != null) return key
        } catch (_: Exception) {
        }

        // 3. Try platform default KeyFactory (e.g. Conscrypt on Android 15/16)
        try {
            val defaultKf = KeyFactory.getInstance("RSA")
            val key = defaultKf.generatePrivate(spec) as? RSAPrivateCrtKey
            if (key != null) return key
        } catch (_: Exception) {
        }

        return null
    }

    /**
     * Derives an RSA [KeyPair] from the given [RSAPrivateCrtKey] by extracting
     * modulus and publicExponent and constructing the matching [RSAPublicKey]
     * using the BouncyCastle-backed [KeyFactory].
     */
    fun deriveKeyPair(privateKey: RSAPrivateCrtKey): KeyPair {
        val pubSpec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
        val pubKey =
            try {
                CryptoProviders.rsaKeyFactory().generatePublic(pubSpec) as RSAPublicKey
            } catch (_: Exception) {
                KeyFactory.getInstance("RSA").generatePublic(pubSpec) as RSAPublicKey
            }
        return KeyPair(pubKey, privateKey)
    }

    /**
     * Serializes an RSA private key to standard PKCS#8 PEM format (`-----BEGIN PRIVATE KEY-----`).
     * This matches the format used by official Android SDK ADB (~/.android/adbkey).
     */
    fun privateKeyToPem(privateKey: PrivateKey): String =
        X509Generator.privateKeyToPem(privateKey)

    private fun isPkcs1Der(bytes: ByteArray): Boolean {
        return try {
            if (bytes.size < 4 || bytes[0] != 0x30.toByte()) return false
            val buf = java.nio.ByteBuffer.wrap(bytes)
            buf.get() // 0x30
            readDerLength(buf)
            if (buf.remaining() < 3) return false
            if (buf.get() != 0x02.toByte()) return false // Version tag 0x02
            val versionLen = readDerLength(buf)
            if (buf.remaining() < versionLen + 1) return false
            buf.position(buf.position() + versionLen)
            buf.hasRemaining() && buf.get() == 0x02.toByte() // Modulus tag 0x02
        } catch (_: Exception) {
            false
        }
    }

    private fun parsePkcs1PrivateKey(der: ByteArray): RSAPrivateCrtKey? {
        return try {
            val buffer = java.nio.ByteBuffer.wrap(der)
            require(buffer.get() == 0x30.toByte()) { "Invalid DER sequence" }
            readDerLength(buffer)

            readDerInteger(buffer) // Version

            val modulus = readDerInteger(buffer)
            val publicExponent = readDerInteger(buffer)
            val privateExponent = readDerInteger(buffer)
            val prime1 = readDerInteger(buffer)
            val prime2 = readDerInteger(buffer)
            val exponent1 = readDerInteger(buffer)
            val exponent2 = readDerInteger(buffer)
            val coefficient = readDerInteger(buffer)

            val spec =
                RSAPrivateCrtKeySpec(
                    modulus,
                    publicExponent,
                    privateExponent,
                    prime1,
                    prime2,
                    exponent1,
                    exponent2,
                    coefficient,
                )
            val key =
                try {
                    CryptoProviders.rsaKeyFactory().generatePrivate(spec) as? RSAPrivateCrtKey
                } catch (_: Exception) {
                    null
                } ?: try {
                    KeyFactory.getInstance("RSA").generatePrivate(spec) as? RSAPrivateCrtKey
                } catch (_: Exception) {
                    null
                }
            key
        } catch (_: Exception) {
            null
        }
    }

    private fun readDerLength(buf: java.nio.ByteBuffer): Int {
        var len = buf.get().toInt() and 0xFF
        if ((len and 0x80) != 0) {
            val count = len and 0x7F
            require(count != 0) { "Indefinite-length DER encoding is not valid here" }
            len = 0
            for (i in 0 until count) {
                len = (len shl 8) or (buf.get().toInt() and 0xFF)
            }
        }
        return len
    }

    private fun readDerInteger(buf: java.nio.ByteBuffer): BigInteger {
        require(buf.get() == 0x02.toByte()) { "Expected DER Integer tag 0x02" }
        val len = readDerLength(buf)
        val bytes = ByteArray(len)
        buf.get(bytes)
        return BigInteger(bytes)
    }

    /** Signs the 20 byte SHA1 token adbd sends during AUTH. */
    fun signToken(
        privateKey: PrivateKey,
        token: ByteArray,
    ): ByteArray {
        val sha1DigestInfoPrefix =
            byteArrayOf(
                0x30,
                0x21,
                0x30,
                0x09,
                0x06,
                0x05,
                0x2b,
                0x0e,
                0x03,
                0x02,
                0x1a,
                0x05,
                0x00,
                0x04,
                0x14,
            )
        val digestInfo = sha1DigestInfoPrefix + token
        val cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, privateKey)
        return cipher.doFinal(digestInfo)
    }

    /**
     * Encodes an RSA public key into the raw binary ADB mincrypt structure
     * (modulus_size_words, n0inv, modulus, RR, exponent all little endian).
     * This is the cryptographic identity of the key: no comment, no username,
     * fully deterministic given the same key. Use this (not [encodePublicKeyAdb])
     * whenever you need something stable to hash, compare, or fingerprint.
     */
    fun encodePublicKeyBlob(publicKey: RSAPublicKey): ByteArray {
        val words = 64
        val n = publicKey.modulus
        val e = publicKey.publicExponent

        var eVal = e.toLong().toInt()
        if (eVal == 0) eVal = 65537

        val nWords = biguintToLeU32Words(n, words)
        val n0inv = computeN0Inv(n)

        val rSquared = computeRSquared(n, words)
        val rrWords = biguintToLeU32Words(rSquared, words)

        val buf = java.io.ByteArrayOutputStream()
        writeLeU32(buf, words)
        writeLeU32(buf, n0inv)
        for (w in nWords) writeLeU32(buf, w)
        for (w in rrWords) writeLeU32(buf, w)
        writeLeU32(buf, eVal)

        return buf.toByteArray()
    }

    /**
     * Encodes RSA public key in the format adb actually writes to adbkey.pub
     * and sends over the wire: Base64(mincrypt blob) + " " + user@host + NUL.
     * The trailing "user@host" is a display comment only .... it is not part of
     * the key's identity and differs between machines/regenerations. Do not
     * hash this output expecting a stable fingerprint; use
     * [encodePublicKeyBlob] for that instead.
     */
    fun encodePublicKeyAdb(
        publicKey: RSAPublicKey,
        identityComment: String = "${System.getProperty("user.name") ?: "user"}@adb_kt",
    ): ByteArray {
        val blob = encodePublicKeyBlob(publicKey)
        val b64 = Base64.getEncoder().encodeToString(blob)
        val comment = identityComment.ifBlank { "${System.getProperty("user.name") ?: "user"}@adb_kt" }
        return "$b64 $comment\u0000".toByteArray(Charsets.US_ASCII)
    }

    private fun writeLeU32(
        out: java.io.ByteArrayOutputStream,
        v: Int,
    ) {
        out.write(v and 0xFF)
        out.write((v ushr 8) and 0xFF)
        out.write((v ushr 16) and 0xFF)
        out.write((v ushr 24) and 0xFF)
    }

    private fun computeN0Inv(n: BigInteger): Int {
        val r32 = BigInteger.valueOf(2).pow(32)
        val n0 = n.mod(r32)
        val inv = n0.modInverse(r32)
        return r32
            .subtract(inv)
            .mod(r32)
            .toLong()
            .toInt()
    }

    private fun computeRSquared(
        n: BigInteger,
        words: Int,
    ): BigInteger {
        val bits = 64 * words
        val rSq = BigInteger.ONE.shiftLeft(bits)
        return rSq.mod(n)
    }

    private fun biguintToLeU32Words(
        n: BigInteger,
        words: Int,
    ): IntArray {
        var bytes = n.toByteArray()
        if (bytes.isNotEmpty() && bytes[0].toInt() == 0) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }
        val targetByteLen = words * 4
        val paddedBigEndian = ByteArray(targetByteLen)
        if (bytes.size <= targetByteLen) {
            System.arraycopy(bytes, 0, paddedBigEndian, targetByteLen - bytes.size, bytes.size)
        } else {
            System.arraycopy(bytes, bytes.size - targetByteLen, paddedBigEndian, 0, targetByteLen)
        }
        paddedBigEndian.reverse()

        val out = IntArray(words)
        for (i in 0 until words) {
            val o = i * 4
            out[i] = (paddedBigEndian[o].toInt() and 0xFF) or
                ((paddedBigEndian[o + 1].toInt() and 0xFF) shl 8) or
                ((paddedBigEndian[o + 2].toInt() and 0xFF) shl 16) or
                ((paddedBigEndian[o + 3].toInt() and 0xFF) shl 24)
        }
        return out
    }
}
