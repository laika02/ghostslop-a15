package io.github.rhythmcache.adb.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Provider

object CryptoProviders {
    val provider: Provider = BouncyCastleProvider()

    fun rsaKeyFactory(): KeyFactory = KeyFactory.getInstance("RSA", provider)

    fun rsaKeyPairGenerator(): KeyPairGenerator = KeyPairGenerator.getInstance("RSA", provider)

    fun getKeyFactory(): KeyFactory = rsaKeyFactory()
}
