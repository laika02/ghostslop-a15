package io.github.rhythmcache.adb.io

import java.io.Closeable
import java.io.EOFException
import java.io.File
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * A seekable random access byte source for ADB sideload and rescue operations.
 *
 * The sideload-host / rescue-install wire protocols allow the target device to request
 * blocks out of order (and re-request blocks), requiring positional random-access seeking.
 *
 * Constructors:
 *  - [of] File/path -> Plain file on disk.
 *  - [of] FileDescriptor -> Android SAF: `contentResolver.openFileDescriptor(uri, "r")`
 *    provides a `ParcelFileDescriptor`. Pass `pfd.fileDescriptor` and `pfd.statSize`.
 */
interface RandomAccessSource : Closeable {
    val size: Long

    /** Reads exactly [length] bytes starting at [offset] into [buffer] (from index 0). */
    fun readFullyAt(
        offset: Long,
        buffer: ByteArray,
        length: Int,
    )

    companion object {
        fun of(file: File): RandomAccessSource =
            object : RandomAccessSource {
                private val raf = RandomAccessFile(file, "r")
                override val size: Long = raf.length()

                override fun readFullyAt(
                    offset: Long,
                    buffer: ByteArray,
                    length: Int,
                ) {
                    raf.seek(offset)
                    raf.readFully(buffer, 0, length)
                }

                override fun close() = raf.close()
            }

        fun of(
            fd: FileDescriptor,
            knownSize: Long,
        ): RandomAccessSource =
            object : RandomAccessSource {
                private val channel: FileChannel = FileInputStream(fd).channel
                override val size: Long = knownSize

                override fun readFullyAt(
                    offset: Long,
                    buffer: ByteArray,
                    length: Int,
                ) {
                    val bb = ByteBuffer.wrap(buffer, 0, length)
                    var pos = offset
                    var remaining = length
                    while (remaining > 0) {
                        val read = channel.read(bb, pos)
                        if (read < 0) throw EOFException("Unexpected EOF at offset $pos")
                        pos += read
                        remaining -= read
                    }
                }

                override fun close() = channel.close()
            }
    }
}
