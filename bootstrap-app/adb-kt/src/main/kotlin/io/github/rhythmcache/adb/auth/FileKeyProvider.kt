package io.github.rhythmcache.adb

import java.io.File
import java.security.KeyPair
import java.security.interfaces.RSAPublicKey

class FileKeyProvider(
    private val keyFile: File,
    private val pubKeyFile: File? = null,
    private val identityComment: String? = null,
) : AdbKeyProvider {
    private var loadedKeyPair: KeyPair? = null

    override suspend fun getAdbPublicKeyBytes(): ByteArray? {
        if (identityComment != null) {
            val kp = getKeyPair()
            val pubKey = kp.public as RSAPublicKey
            return AdbAuth.encodePublicKeyAdb(pubKey, identityComment)
        }
        val targetPub = pubKeyFile ?: File(keyFile.parentFile ?: File("."), "${keyFile.name}.pub")
        if (targetPub.exists() && targetPub.length() > 0) {
            try {
                val text = targetPub.readText(Charsets.US_ASCII).trim()
                if (text.isNotBlank()) {
                    return if (text.endsWith(
                            "\u0000",
                        )
                    ) {
                        text.toByteArray(Charsets.US_ASCII)
                    } else {
                        "$text\u0000".toByteArray(Charsets.US_ASCII)
                    }
                }
            } catch (_: Exception) {
            }
        }
        val kp = getKeyPair()
        val pubKey = kp.public as RSAPublicKey
        return AdbAuth.encodePublicKeyAdb(pubKey)
    }

    override suspend fun getKeyPair(): KeyPair {
        loadedKeyPair?.let { return it }

        if (keyFile.exists() && keyFile.length() > 0) {
            try {
                val rawBytes = keyFile.readBytes()
                val privKey =
                    AdbAuth.parsePrivateKey(rawBytes)
                        ?: throw AdbException.Authentication("Failed to load RSA key pair from '${keyFile.absolutePath}': Unrecognized key format")
                val kp = AdbAuth.deriveKeyPair(privKey)
                loadedKeyPair = kp
                return kp
            } catch (e: Exception) {
                if (e is AdbException) throw e
                throw AdbException.Authentication("Failed to load RSA key pair from '${keyFile.absolutePath}': ${e.message}")
            }
        }

        val generated = AdbAuth.generateKey()
        try {
            keyFile.parentFile?.mkdirs()
            keyFile.writeBytes(generated.private.encoded)
            val pubBytes =
                if (identityComment != null) {
                    AdbAuth.encodePublicKeyAdb(generated.public as RSAPublicKey, identityComment)
                } else {
                    AdbAuth.encodePublicKeyAdb(generated.public as RSAPublicKey)
                }
            val targetPubFile = pubKeyFile ?: File(keyFile.parentFile, "${keyFile.name}.pub")
            targetPubFile.writeBytes(pubBytes)
        } catch (_: Exception) {
        }
        loadedKeyPair = generated
        return generated
    }
}
