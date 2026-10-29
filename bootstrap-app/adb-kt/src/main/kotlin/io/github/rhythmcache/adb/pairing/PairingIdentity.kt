package io.github.rhythmcache.adb.pairing

import io.github.rhythmcache.adb.AdbKeyProvider
import io.github.rhythmcache.adb.crypto.X509Generator

/**
 * Builds a PairingIdentity from an existing AdbKeyProvider, reusing the
 * long-term ADB auth keypair for the pairing/transport X.509 cert -- matches
 * AOSP's adb_wifi_pair_device, which signs the pairing cert with
 * adb_auth_get_user_privkey() rather than minting a separate identity.
 */
suspend fun buildPairingIdentity(keyProvider: AdbKeyProvider): PairingIdentity {
    val keyPair = keyProvider.getKeyPair()
    val cert = X509Generator.generate(keyPair)
    return PairingIdentity(
        keyPair = keyPair,
        certPem = X509Generator.toPem(cert),
        privateKeyPem = X509Generator.privateKeyToPem(keyPair.private),
    )
}
