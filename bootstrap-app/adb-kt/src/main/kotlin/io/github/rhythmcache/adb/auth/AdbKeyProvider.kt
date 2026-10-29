package io.github.rhythmcache.adb

import java.security.KeyPair

interface AdbKeyProvider {
    suspend fun getKeyPair(): KeyPair

    suspend fun getAdbPublicKeyBytes(): ByteArray? = null

    companion object {
        fun from(
            keyPair: KeyPair,
            identityComment: String? = null,
        ): AdbKeyProvider = MemoryKeyProvider(customKeyPair = keyPair, identityComment = identityComment)
    }
}
