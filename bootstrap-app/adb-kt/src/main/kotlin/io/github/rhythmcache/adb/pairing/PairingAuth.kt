package io.github.rhythmcache.adb.pairing

import io.github.rhythmache.spake2.Spake2Ctx
import io.github.rhythmache.spake2.Spake2Role
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val AES_KEY_LEN = 16 // AES-128
private const val GCM_TAG_LEN_BITS = 128 // EVP_AEAD_DEFAULT_TAG_LENGTH for aes-128-gcm = 16 bytes
private const val GCM_NONCE_LEN = 12 // AEAD_AES_128_GCM nonce length

private val CLIENT_NAME = "adb pair client\u0000".toByteArray(Charsets.US_ASCII)
private val SERVER_NAME = "adb pair server\u0000".toByteArray(Charsets.US_ASCII)
private val HKDF_INFO = "adb pairing_auth aes-128-gcm key".toByteArray(Charsets.US_ASCII)

enum class PairingRole { CLIENT, SERVER }

/**
 * taken from PairingAuthCtx (pairing_auth.cpp) of AOSP. Wraps SPAKE2 + HKDF-derived
 * AES-128-GCM cipher for the ADB pairing protocol.
 *
 * Usage:
 *   val auth = PairingAuthCtx(PairingRole.CLIENT, password)
 *   send(auth.ourMsg)
 *   auth.initCipher(theirMsg)   // call exactly once
 *   val enc = auth.encrypt(peerInfoBytes)
 *   val dec = auth.decrypt(theirEncBytes)
 */
class PairingAuthCtx(
    role: PairingRole,
    password: ByteArray,
) {
    private val spake2: Spake2Ctx

    /** Our SPAKE2 message. Always non-empty once constructed. */
    val ourMsg: ByteArray

    private var cipherState: CipherState? = null
    private var cipherInitialized = false

    init {
        require(password.isNotEmpty()) { "password must not be empty" }

        spake2 =
            when (role) {
                PairingRole.CLIENT -> Spake2Ctx(Spake2Role.ALICE, CLIENT_NAME, SERVER_NAME)
                PairingRole.SERVER -> Spake2Ctx(Spake2Role.BOB, SERVER_NAME, CLIENT_NAME)
            }

        ourMsg = spake2.generateMessage(password)
    }

    /**
     * Processes the peer's SPAKE2 message and initializes the AEAD cipher.
     * Can only be called once. Returns true on success (i.e. the SPAKE2
     * exchange produced key material and the cipher was set up) — this does
     * NOT yet prove the passwords matched; that's only known once you can
     * successfully decrypt something the peer encrypted with their side of
     * the key.
     */
    fun initCipher(theirMsg: ByteArray): Boolean {
        check(!cipherInitialized) { "initCipher() already called" }
        cipherInitialized = true

        if (theirMsg.size != 32) return false

        val keyMaterial =
            try {
                spake2.processMessage(theirMsg)
            } catch (e: Exception) {
                return false
            }

        val aesKey = hkdfSha256(keyMaterial, HKDF_INFO, AES_KEY_LEN)
        cipherState = CipherState(aesKey)
        return true
    }

    private fun requireCipher(): CipherState = cipherState ?: error("Cipher not initialized: call initCipher() successfully first")

    /** Encrypts [data], returns ciphertext+tag, or null on failure. */
    fun encrypt(data: ByteArray): ByteArray? = requireCipher().encrypt(data)

    /** Decrypts [data], returns plaintext, or null on failure (e.g. wrong password). */
    fun decrypt(data: ByteArray): ByteArray? = requireCipher().decrypt(data)

    companion object {
        /**
         * HKDF-SHA256 (extract-and-expand), matching BoringSSL's HKDF() with
         * no salt (nullptr, 0 passed as salt in aes_128_gcm.cpp).
         */
        private fun hkdfSha256(
            ikm: ByteArray,
            info: ByteArray,
            outLen: Int,
        ): ByteArray {
            val hmacAlg = "HmacSHA256"
            val hashLen = 32

            // Extract: PRK = HMAC-SHA256(salt=empty-32-zero-key, IKM)
            // Per RFC 5869: if salt not provided, use a string of HashLen zeros.
            val emptySalt = ByteArray(hashLen)
            val extractMac = Mac.getInstance(hmacAlg)
            extractMac.init(SecretKeySpec(emptySalt, hmacAlg))
            val prk = extractMac.doFinal(ikm)

            // Expand
            val expandMac = Mac.getInstance(hmacAlg)
            expandMac.init(SecretKeySpec(prk, hmacAlg))

            val n = (outLen + hashLen - 1) / hashLen
            require(n <= 255) { "HKDF output too large" }

            var previousBlock = ByteArray(0)
            val okm = ByteArray(n * hashLen)
            for (i in 1..n) {
                expandMac.reset()
                expandMac.update(previousBlock)
                expandMac.update(info)
                expandMac.update(i.toByte())
                previousBlock = expandMac.doFinal()
                System.arraycopy(previousBlock, 0, okm, (i - 1) * hashLen, hashLen)
            }

            return okm.copyOf(outLen)
        }
    }

    /**
     * Mirrors Aes128Gcm: sequence-number-derived nonces, separate counters
     * for encrypt and decrypt directions. NOT thread-safe; call encrypt/decrypt
     * from a single coroutine/thread per PairingAuthCtx instance.
     */
    private class CipherState(
        keyBytes: ByteArray,
    ) {
        private val key = SecretKeySpec(keyBytes, "AES")
        private var encSeq = 0L
        private var decSeq = 0L

        fun encrypt(plaintext: ByteArray): ByteArray? =
            try {
                val nonce = nonceFromSeq(encSeq)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LEN_BITS, nonce))
                val out = cipher.doFinal(plaintext)
                encSeq++
                out
            } catch (e: Exception) {
                null
            }

        fun decrypt(ciphertext: ByteArray): ByteArray? =
            try {
                val nonce = nonceFromSeq(decSeq)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LEN_BITS, nonce))
                val out = cipher.doFinal(ciphertext)
                decSeq++
                out
            } catch (e: Exception) {
                null
            }

        /**
         * Nonce = 12 bytes, little-endian 8-byte sequence counter placed at
         * the start, remaining bytes zero. Matches:
         *   memcpy(nonce.data(), &enc_sequence_, sizeof(enc_sequence_));
         * where enc_sequence_ is a native uint64_t (little-endian on all
         * relevant platforms) and nonce.size() == 12.
         */
        private fun nonceFromSeq(seq: Long): ByteArray {
            val nonce = ByteArray(GCM_NONCE_LEN)
            val buf = ByteBuffer.wrap(nonce, 0, 8).order(ByteOrder.LITTLE_ENDIAN)
            buf.putLong(seq)
            return nonce
        }
    }
}
