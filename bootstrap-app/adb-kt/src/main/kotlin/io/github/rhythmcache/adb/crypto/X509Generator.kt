package io.github.rhythmcache.adb.crypto

import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * Port of x509_generator.cpp. Generates the self-signed X.509 certificate
 * ADB uses to establish identity for both pairing and TLS transport.
 * Matches AOSP exactly: 10-year validity, C=US/O=Android/CN=Adb subject
 * (self-issued), basicConstraints CA:TRUE, keyUsage keyCertSign+cRLSign+
 * digitalSignature, SHA-256 signature.
 */
object X509Generator {
    private const val CERT_LIFETIME_SECONDS = 10L * 365 * 24 * 60 * 60

    /** Generates a self-signed X.509 certificate for [keyPair]. */
    fun generate(keyPair: KeyPair): X509Certificate {
        val subject = X500Principal("C=US,O=Android,CN=Adb")
        val serial = BigInteger.ONE
        val notBefore = Date()
        val notAfter = Date(notBefore.time + CERT_LIFETIME_SECONDS * 1000)

        // issuer == subject (self-signed)
        val builder: X509v3CertificateBuilder =
            JcaX509v3CertificateBuilder(
                subject,
                serial,
                notBefore,
                notAfter,
                subject,
                keyPair.public,
            )

        val extUtils = JcaX509ExtensionUtils()

        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(
            Extension.keyUsage,
            true,
            KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign or KeyUsage.digitalSignature),
        )
        // matches AOSP: only basicConstraints and keyUsage are marked critical
        builder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            extUtils.createSubjectKeyIdentifier(keyPair.public),
        )

        val signer =
            JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(CryptoProviders.provider)
                .build(keyPair.private)

        val holder = builder.build(signer)
        return JcaX509CertificateConverter()
            .setProvider(CryptoProviders.provider)
            .getCertificate(holder)
    }

    /** Serializes a certificate to PEM format. */
    fun toPem(cert: X509Certificate): String {
        val sw = StringWriter()
        PemWriter(sw).use { it.writeObject(PemObject("CERTIFICATE", cert.encoded)) }
        return sw.toString()
    }

    /** Serializes a private key to PEM (PKCS8) format. */
    fun privateKeyToPem(privateKey: java.security.PrivateKey): String {
        val sw = StringWriter()
        PemWriter(sw).use { it.writeObject(PemObject("PRIVATE KEY", privateKey.encoded)) }
        return sw.toString()
    }
}
