package io.github.rhythmcache.adb.sync

import io.github.rhythmcache.adb.AdbConnection
import java.io.FileDescriptor
import java.io.InputStream
import java.io.OutputStream

class AdbSync internal constructor(
    private val connection: AdbConnection,
) {
    suspend fun stat(
        remotePath: String,
        followSymlinks: Boolean = false,
    ): AdbFileStat = connection.withSync { it.stat(remotePath, followSymlinks) }

    suspend fun pull(
        remotePath: String,
        output: OutputStream,
        onProgress: ((bytesDone: Long) -> Unit)? = null,
    ) = connection.withSync { it.pull(remotePath, output, onProgress) }

    suspend fun pull(
        remotePath: String,
        fd: FileDescriptor,
        onProgress: ((bytesDone: Long) -> Unit)? = null,
    ) = connection.withSync { it.pull(remotePath, fd, onProgress) }

    suspend fun push(
        input: InputStream,
        remotePath: String,
        mode: Int = 33188,
        mtime: Int = (System.currentTimeMillis() / 1000).toInt(),
        onProgress: ((bytesDone: Long) -> Unit)? = null,
    ) = connection.withSync { it.push(input, remotePath, mode, mtime, onProgress) }

    suspend fun push(
        fd: FileDescriptor,
        remotePath: String,
        mode: Int = 33188,
        mtime: Int = (System.currentTimeMillis() / 1000).toInt(),
        onProgress: ((bytesDone: Long) -> Unit)? = null,
    ) = connection.withSync { it.push(fd, remotePath, mode, mtime, onProgress) }
}
