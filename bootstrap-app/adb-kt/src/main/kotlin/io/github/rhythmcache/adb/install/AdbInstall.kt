package io.github.rhythmcache.adb.install

import io.github.rhythmcache.adb.AdbConnection
import io.github.rhythmcache.adb.AdbException
import io.github.rhythmcache.adb.io.RandomAccessSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import java.io.File
import java.io.InputStream

data class InstallProgress(
    val bytesTransferred: Long,
    val totalBytes: Long,
    val percentage: Float,
    val statusText: String = "",
)

data class InstallResult(
    val isSuccess: Boolean,
    val message: String,
)

class AdbInstall(
    private val connection: AdbConnection,
) {
    companion object {
        const val DEFAULT_BUFFER_SIZE = 64 * 1024 // 64KB
    }

    /**
     * Install a single APK streaming directly from a File.
     */
    fun install(
        file: File,
        flags: List<String> = listOf("-r"),
        bufferSize: Int = DEFAULT_BUFFER_SIZE,
    ): Flow<InstallProgress> = install(RandomAccessSource.of(file), flags, bufferSize)

    /**
     * Install a single APK streaming directly from a [RandomAccessSource].
     * Closes [source] when done (success, failure, or cancellation).
     */
    fun install(
        source: RandomAccessSource,
        flags: List<String> = listOf("-r"),
        bufferSize: Int = DEFAULT_BUFFER_SIZE,
    ): Flow<InstallProgress> =
        flow {
            val totalSize = source.size
            val flagStr = if (flags.isNotEmpty()) flags.joinToString(" ", postfix = " ") else ""
            val service = "exec:cmd package install $flagStr-S $totalSize"
            val stream = connection.open(service)
            source.use {
                try {
                    val buffer = ByteArray(bufferSize)
                    var sent = 0L
                    while (sent < totalSize) {
                        val chunkSize = minOf(buffer.size.toLong(), totalSize - sent).toInt()
                        source.readFullyAt(sent, buffer, chunkSize)
                        val chunk = if (chunkSize == buffer.size) buffer else buffer.copyOf(chunkSize)
                        stream.write(chunk)
                        sent += chunkSize
                        val percent = ((sent.toDouble() / totalSize.toDouble()) * 100).toFloat().coerceIn(0f, 100f)
                        emit(InstallProgress(sent, totalSize, percent, "Streaming APK..."))
                    }
                    val responseBytes = stream.readToEnd()
                    val response = String(responseBytes, Charsets.UTF_8).trim()
                    if (!response.startsWith("Success")) {
                        throw AdbException.Protocol("Installation failed: $response")
                    }
                    emit(InstallProgress(totalSize, totalSize, 100f, "Success"))
                } finally {
                    stream.close()
                }
            }
        }.flowOn(Dispatchers.IO)

    /**
     * Install a single APK streaming directly from an [InputStream].
     *
     * Only appropriate for genuinely sequential sources (lets say a network stream).
     * If you already have a SAF Uri, prefer opening it as a [RandomAccessSource]
     * via `ParcelFileDescriptor` and using [install] instead.
     * This overload does NOT close [inputStream]; the caller owns it.
     */
    fun installStream(
        inputStream: InputStream,
        totalSize: Long,
        flags: List<String> = listOf("-r"),
        bufferSize: Int = DEFAULT_BUFFER_SIZE,
    ): Flow<InstallProgress> =
        flow {
            val flagStr = if (flags.isNotEmpty()) flags.joinToString(" ", postfix = " ") else ""
            val service = "exec:cmd package install $flagStr-S $totalSize"
            val stream = connection.open(service)
            try {
                val buffer = ByteArray(bufferSize)
                var sent = 0L
                while (sent < totalSize) {
                    val toRead = minOf(buffer.size.toLong(), totalSize - sent).toInt()
                    val read = inputStream.read(buffer, 0, toRead)
                    if (read <= 0) break
                    val chunk = if (read == buffer.size) buffer else buffer.copyOf(read)
                    stream.write(chunk)
                    sent += read
                    val percent = ((sent.toDouble() / totalSize.toDouble()) * 100).toFloat().coerceIn(0f, 100f)
                    emit(InstallProgress(sent, totalSize, percent, "Streaming APK..."))
                }
                val responseBytes = stream.readToEnd()
                val response = String(responseBytes, Charsets.UTF_8).trim()
                if (!response.startsWith("Success")) {
                    throw AdbException.Protocol("Installation failed: $response")
                }
                emit(InstallProgress(totalSize, totalSize, 100f, "Success"))
            } finally {
                stream.close()
            }
        }.flowOn(Dispatchers.IO)

    /**
     * Install multiple split APKs (App Bundles / .apks) in a single install session.
     * Every [RandomAccessSource] in [splits] is closed when this completes, whether
     * by success, failure, or cancellation.
     */
    fun installMultiple(
        splits: List<Pair<String, RandomAccessSource>>,
        flags: List<String> = listOf("-r"),
        bufferSize: Int = DEFAULT_BUFFER_SIZE,
    ): Flow<InstallProgress> =
        flow {
            val totalSize = splits.sumOf { it.second.size }
            val flagStr = if (flags.isNotEmpty()) flags.joinToString(" ", postfix = " ") else ""
            val createService = "exec:cmd package install-create $flagStr-S $totalSize"

            try {
                val createStream = connection.open(createService)
                val createResponse =
                    try {
                        String(createStream.readToEnd(), Charsets.UTF_8).trim()
                    } finally {
                        createStream.close()
                    }
                if (!createResponse.startsWith("Success")) {
                    throw AdbException.Protocol("Failed to create install session: $createResponse")
                }
                val sessionId =
                    createResponse.substringAfter("[").substringBefore("]").toIntOrNull()
                        ?: throw AdbException.Protocol("Invalid session ID returned: $createResponse")

                var overallSent = 0L
                var isSuccess = false
                try {
                    splits.forEachIndexed { index, (name, source) ->
                        val apkSize = source.size
                        val writeService = "exec:cmd package install-write -S $apkSize $sessionId split_$index.apk -"
                        val writeStream = connection.open(writeService)
                        try {
                            val buffer = ByteArray(bufferSize)
                            var apkSent = 0L
                            while (apkSent < apkSize) {
                                val chunkSize = minOf(buffer.size.toLong(), apkSize - apkSent).toInt()
                                source.readFullyAt(apkSent, buffer, chunkSize)
                                val chunk = if (chunkSize == buffer.size) buffer else buffer.copyOf(chunkSize)
                                writeStream.write(chunk)
                                apkSent += chunkSize
                                overallSent += chunkSize
                                val percent = ((overallSent.toDouble() / totalSize.toDouble()) * 100).toFloat().coerceIn(0f, 100f)
                                emit(InstallProgress(overallSent, totalSize, percent, "Writing $name..."))
                            }
                            val writeResp = String(writeStream.readToEnd(), Charsets.UTF_8).trim()
                            if (!writeResp.startsWith("Success")) {
                                throw AdbException.Protocol("Failed writing split $name: $writeResp")
                            }
                        } finally {
                            writeStream.close()
                        }
                    }
                    val commitStream = connection.open("exec:cmd package install-commit $sessionId")
                    val commitResponse =
                        try {
                            String(commitStream.readToEnd(), Charsets.UTF_8).trim()
                        } finally {
                            commitStream.close()
                        }
                    if (!commitResponse.startsWith("Success")) {
                        throw AdbException.Protocol("Failed committing install session: $commitResponse")
                    }
                    isSuccess = true
                    emit(InstallProgress(totalSize, totalSize, 100f, "Success"))
                } finally {
                    if (!isSuccess) {
                        try {
                            val abandonStream = connection.open("exec:cmd package install-abandon $sessionId")
                            abandonStream.close()
                        } catch (_: Exception) {
                            // best effort cleanup; original failure is what propagates
                        }
                    }
                }
            } finally {
                // always release every split's underlying resource (fd, RandomAccessFile, etc.)
                // regardless of where in the session this failed or whether it succeeded.
                for ((_, source) in splits) {
                    try {
                        source.close()
                    } catch (_: Exception) {
                        // ignore secondary close failures
                    }
                }
            }
        }.flowOn(Dispatchers.IO)
}
