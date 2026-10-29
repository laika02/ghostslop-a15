package io.github.rhythmcache.adb.sideload

import io.github.rhythmcache.adb.AdbConnection
import io.github.rhythmcache.adb.AdbException
import io.github.rhythmcache.adb.io.RandomAccessSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import java.io.EOFException
import java.io.File

data class SideloadProgress(
    val bytesTransferred: Long,
    val totalBytes: Long,
    val percentage: Float,
)

class AdbSideload(
    private val connection: AdbConnection,
) {
    companion object {
        const val DEFAULT_BLOCK_SIZE = 64 * 1024 // 64KB
    }

    /** Convenience overload for plain File */
    fun sideload(
        file: File,
        blockSize: Int = DEFAULT_BLOCK_SIZE,
    ): Flow<SideloadProgress> = sideload(RandomAccessSource.of(file), blockSize)

    /**
     * Sideload an OTA package over ADB using a [RandomAccessSource].
     * Automatically attempts modern `sideload-host` demand protocol first,
     * falling back to pre-KitKat `sideload:` stream protocol on failure.
     */
    fun sideload(
        source: RandomAccessSource,
        blockSize: Int = DEFAULT_BLOCK_SIZE,
    ): Flow<SideloadProgress> =
        flow {
            val fileSize = source.size
            val service = "sideload-host:$fileSize:$blockSize"

            val hostStream =
                try {
                    connection.open(service)
                } catch (_: Exception) {
                    null
                }

            source.use {
                if (hostStream != null) {
                    // Modern sideload-host block demand protocol
                    try {
                        var bytesTransferred = 0L
                        val reqBuf = ByteArray(8)
                        while (true) {
                            try {
                                hostStream.readFully(reqBuf)
                            } catch (_: EOFException) {
                                break
                            }
                            val reqStr = String(reqBuf, Charsets.UTF_8)

                            if (reqStr == "DONEDONE") {
                                emit(SideloadProgress(fileSize, fileSize, 100f))
                                break
                            }
                            if (reqStr == "FAILFAIL") {
                                throw AdbException.Protocol("Device reported sideload failure")
                            }

                            val blockNum =
                                reqStr.toLongOrNull()
                                    ?: throw AdbException.Protocol("Invalid block request from device: $reqStr")

                            val offset = blockNum * blockSize
                            if (offset >= fileSize) break

                            val currentChunkSize = minOf(blockSize.toLong(), fileSize - offset).toInt()
                            val buffer = ByteArray(currentChunkSize)
                            source.readFullyAt(offset, buffer, currentChunkSize)

                            hostStream.write(buffer)

                            bytesTransferred += currentChunkSize
                            val percent = ((offset.toDouble() / fileSize.toDouble()) * 100).toFloat().coerceIn(0f, 100f)
                            emit(SideloadProgress(bytesTransferred, fileSize, percent))
                        }
                    } finally {
                        hostStream.close()
                    }
                } else {
                    // Legacy pre-KitKat streaming sideload protocol (sequential, forward-only)
                    val legacyStream = connection.open("sideload:$fileSize")
                    try {
                        val buffer = ByteArray(blockSize)
                        var sent = 0L
                        while (sent < fileSize) {
                            val chunkSize = minOf(buffer.size.toLong(), fileSize - sent).toInt()
                            source.readFullyAt(sent, buffer, chunkSize)
                            val chunk = if (chunkSize == buffer.size) buffer else buffer.copyOf(chunkSize)
                            legacyStream.write(chunk)
                            sent += chunkSize
                            val percent = ((sent.toDouble() / fileSize.toDouble()) * 100).toFloat().coerceIn(0f, 100f)
                            emit(SideloadProgress(sent, fileSize, percent))
                        }
                    } finally {
                        legacyStream.close()
                    }
                }
            }
        }.flowOn(Dispatchers.IO)
}
