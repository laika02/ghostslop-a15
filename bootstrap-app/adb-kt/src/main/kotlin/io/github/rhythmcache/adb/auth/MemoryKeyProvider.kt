package io.github.rhythmcache.adb

import java.security.KeyPair
import java.security.interfaces.RSAPublicKey

open class MemoryKeyProvider(
    private val customKeyPair: KeyPair? = null,
    private val identityComment: String? = null,
) : AdbKeyProvider {
    private val keyPairInstance by lazy { customKeyPair ?: AdbAuth.generateKey() }

    override suspend fun getKeyPair(): KeyPair = keyPairInstance

    override suspend fun getAdbPublicKeyBytes(): ByteArray? {
        val kp = getKeyPair()
        val pubKey = kp.public as RSAPublicKey
        return if (identityComment != null) {
            AdbAuth.encodePublicKeyAdb(pubKey, identityComment)
        } else {
            AdbAuth.encodePublicKeyAdb(pubKey)
        }
    }

    companion object : MemoryKeyProvider()
}
