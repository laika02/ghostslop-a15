package io.github.rhythmcache.adb.pairing

import io.github.rhythmcache.adb.crypto.X509Generator
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.CertificateEntry
import org.bouncycastle.tls.CertificateRequest
import org.bouncycastle.tls.DefaultTlsClient
import org.bouncycastle.tls.DefaultTlsServer
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.SignatureAndHashAlgorithm
import org.bouncycastle.tls.TlsAuthentication
import org.bouncycastle.tls.TlsClientContext
import org.bouncycastle.tls.TlsClientProtocol
import org.bouncycastle.tls.TlsContext
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsProtocol
import org.bouncycastle.tls.TlsServerCertificate
import org.bouncycastle.tls.TlsServerContext
import org.bouncycastle.tls.TlsServerProtocol
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.TlsCrypto
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.x509.Certificate as ASN1Certificate

class PairingTlsSocket private constructor(
    private val protocol: TlsProtocol,
    private val exportedKey: ByteArray,
    val peerCertPem: String?,
    private val rawSocket: Socket,
) {
    companion object {
        private val secureRandom = SecureRandom()
        private val crypto: TlsCrypto = BcTlsCrypto(secureRandom)

        fun connectAsClient(
            rawSocket: Socket,
            certPem: String,
            privateKeyPem: String,
        ): PairingTlsSocket {
            val (certChain, privKey) = parseIdentity(certPem, privateKeyPem)
            var capturedContext: TlsClientContext? = null
            var exportedKey: ByteArray? = null
            var peerCertPem: String? = null

            val client =
                object : DefaultTlsClient(crypto) {
                    override fun getSupportedVersions(): Array<ProtocolVersion> = arrayOf(ProtocolVersion.TLSv13)

                    override fun init(context: TlsClientContext) {
                        capturedContext = context
                        super.init(context)
                    }

                    override fun notifyHandshakeComplete() {
                        super.notifyHandshakeComplete()
                        val ctx = requireNotNull(capturedContext)
                        exportedKey = ctx.exportKeyingMaterial("adb-label\u0000", ByteArray(0), 64)
                    }

                    override fun getAuthentication(): TlsAuthentication =
                        object : TlsAuthentication {
                            override fun notifyServerCertificate(serverCertificate: TlsServerCertificate) {
                                runCatching {
                                    val presented = serverCertificate.certificate.getCertificateAt(0)
                                    val cf = CertificateFactory.getInstance("X.509")
                                    val javaCert =
                                        ByteArrayInputStream(presented.encoded).use {
                                            cf.generateCertificate(it) as X509Certificate
                                        }
                                    peerCertPem = X509Generator.toPem(javaCert)
                                }
                            }

                            override fun getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials =
                                buildCredentials(requireNotNull(capturedContext), certChain, privKey)
                        }
                }

            val protocol = TlsClientProtocol(rawSocket.getInputStream(), rawSocket.getOutputStream())
            protocol.connect(client)

            return PairingTlsSocket(protocol, requireNotNull(exportedKey), peerCertPem, rawSocket)
        }

        fun connectAsServer(
            rawSocket: Socket,
            certPem: String,
            privateKeyPem: String,
        ): PairingTlsSocket {
            val (certChain, privKey) = parseIdentity(certPem, privateKeyPem)
            var capturedContext: TlsServerContext? = null
            var exportedKey: ByteArray? = null
            var peerCertPem: String? = null

            val server =
                object : DefaultTlsServer(crypto) {
                    override fun getSupportedVersions(): Array<ProtocolVersion> = arrayOf(ProtocolVersion.TLSv13)

                    override fun init(context: TlsServerContext) {
                        capturedContext = context
                        super.init(context)
                    }

                    override fun notifyHandshakeComplete() {
                        super.notifyHandshakeComplete()
                        val ctx = requireNotNull(capturedContext)
                        exportedKey = ctx.exportKeyingMaterial("adb-label\u0000", ByteArray(0), 64)
                    }

                    override fun getCertificateRequest(): CertificateRequest? = null

                    override fun notifyClientCertificate(clientCertificate: Certificate) {
                        runCatching {
                            if (!clientCertificate.isEmpty) {
                                val presented = clientCertificate.getCertificateAt(0)
                                val cf = CertificateFactory.getInstance("X.509")
                                val javaCert =
                                    ByteArrayInputStream(presented.encoded).use {
                                        cf.generateCertificate(it) as X509Certificate
                                    }
                                peerCertPem = X509Generator.toPem(javaCert)
                            }
                        }
                    }

                    override fun getCredentials(): TlsCredentials = buildCredentials(requireNotNull(capturedContext), certChain, privKey)
                }

            val protocol = TlsServerProtocol(rawSocket.getInputStream(), rawSocket.getOutputStream())
            protocol.accept(server)

            return PairingTlsSocket(protocol, requireNotNull(exportedKey), peerCertPem, rawSocket)
        }

        private fun buildCredentials(
            context: TlsContext,
            certChain: Certificate,
            privKey: AsymmetricKeyParameter,
        ): TlsCredentials =
            BcDefaultTlsCredentialedSigner(
                TlsCryptoParameters(context),
                crypto as BcTlsCrypto,
                privKey,
                certChain,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
            )

        private fun parseIdentity(
            certPem: String,
            privateKeyPem: String,
        ): Pair<Certificate, AsymmetricKeyParameter> {
            val certHolder =
                PEMParser(java.io.StringReader(certPem)).readObject()
                    as org.bouncycastle.cert.X509CertificateHolder
            val asn1Cert = ASN1Certificate.getInstance(certHolder.encoded)
            val tlsCert: TlsCertificate = crypto.createCertificate(asn1Cert.encoded)
            val certChain = Certificate(ByteArray(0), arrayOf(CertificateEntry(tlsCert, null)))

            val keyObj = PEMParser(java.io.StringReader(privateKeyPem)).readObject()
            val privKey =
                when (keyObj) {
                    is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> PrivateKeyFactory.createKey(keyObj)
                    is org.bouncycastle.openssl.PEMKeyPair -> PrivateKeyFactory.createKey(keyObj.privateKeyInfo)
                    else -> error("Unsupported private key PEM format: ${keyObj?.javaClass}")
                }

            return certChain to privKey
        }
    }

    fun exportKeyingMaterial(length: Int): ByteArray {
        require(length == exportedKey.size) { "Requested key length $length != ${exportedKey.size}" }
        return exportedKey
    }

    fun inputStream(): InputStream = protocol.inputStream

    fun outputStream(): OutputStream = protocol.outputStream

    fun close() {
        runCatching { protocol.close() }
        runCatching { rawSocket.close() }
    }
}
