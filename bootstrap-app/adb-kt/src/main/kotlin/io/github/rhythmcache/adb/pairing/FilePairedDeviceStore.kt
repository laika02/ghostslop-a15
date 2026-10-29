package io.github.rhythmcache.adb.pairing

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Properties

/**
 * Simple file-based PairedDeviceStore for JVM/desktop use. Stores
 * guid -> base64(cert PEM) pairs in a .properties file. Not suitable for
 * Android as-is (no encryption, plain file); Android callers should
 * implement PairedDeviceStore against Room/DataStore/EncryptedSharedPreferences
 * instead.
 */
class FilePairedDeviceStore(
    private val file: File,
) : PairedDeviceStore {
    private val mutex = Mutex()

    override suspend fun save(
        guid: String,
        certPem: String,
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val props = loadProps()
            props.setProperty(
                guid,
                java.util.Base64
                    .getEncoder()
                    .encodeToString(certPem.toByteArray(Charsets.UTF_8)),
            )
            saveProps(props)
        }
    }

    override suspend fun getCert(guid: String): String? =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val encoded = loadProps().getProperty(guid) ?: return@withLock null
                String(
                    java.util.Base64
                        .getDecoder()
                        .decode(encoded),
                    Charsets.UTF_8,
                )
            }
        }

    override suspend fun remove(guid: String) =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val props = loadProps()
                props.remove(guid)
                saveProps(props)
            }
        }

    override suspend fun listPaired(): List<String> =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                loadProps().stringPropertyNames().toList()
            }
        }

    private fun loadProps(): Properties {
        val props = Properties()
        if (file.exists()) {
            file.inputStream().use { props.load(it) }
        }
        return props
    }

    private fun saveProps(props: Properties) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, "${file.name}.tmp")
        tmp.outputStream().use { props.store(it, "ADB paired devices") }
        if (!tmp.renameTo(file)) {
            // Fallback if atomic rename fails across filesystems
            tmp.copyTo(file, overwrite = true)
            tmp.delete()
        }
    }
}
