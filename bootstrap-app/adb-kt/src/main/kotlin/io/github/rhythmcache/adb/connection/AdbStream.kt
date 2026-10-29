package io.github.rhythmcache.adb

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.sync.Semaphore
import java.io.Closeable
import java.io.EOFException
import java.util.concurrent.atomic.AtomicBoolean

internal sealed class StreamCmd {
    data class Write(
        val localId: Int,
        val remoteId: Int,
        val data: ByteArray,
        val offset: Int,
        val length: Int,
    ) : StreamCmd()

    data class Close(
        val localId: Int,
        val remoteId: Int,
    ) : StreamCmd()

    data class AbortOpen(
        val localId: Int,
    ) : StreamCmd()
}

internal class StreamShared(
    val dataChannel: Channel<Result<ByteArray>> = Channel(capacity = Channel.UNLIMITED),
    var openSignal: CompletableDeferred<Int>? = CompletableDeferred(),
    val flowSemaphore: Semaphore = Semaphore(permits = 1, acquiredPermits = 1),
    var remoteId: Int? = null,
    val maxPayload: Int = 4096,
)

class AdbStream internal constructor(
    val localId: Int,
    val remoteId: Int,
    private val dataChannel: Channel<Result<ByteArray>>,
    private val cmdChannel: Channel<StreamCmd>,
    private val flowSemaphore: Semaphore,
    private val maxPayload: Int,
) : Closeable {
    private val closed = AtomicBoolean(false)
    private var pending: ByteArray? = null
    private var pendingOffset = 0

    val isClosed: Boolean get() = closed.get()

    /** Suspends until the next byte chunk arrives, or returns null on EOF. */
    suspend fun recv(): ByteArray? {
        if (closed.get() && pending == null) {
            return null
        }
        pending?.let {
            val data = it.copyOfRange(pendingOffset, it.size)
            pending = null
            pendingOffset = 0
            return data
        }
        val result = dataChannel.receiveCatching()
        if (result.isClosed) {
            val cause = result.exceptionOrNull()
            if (cause != null) {
                throw AdbException.StreamClosed("ADB stream $localId closed with error: ${cause.message}")
            }
            return null
        }
        return result.getOrNull()?.fold(
            onSuccess = { it },
            onFailure = { throw AdbException.StreamClosed("ADB stream $localId error: ${it.message}") },
        )
    }

    /** Reads into [target] array up to [byteCount] bytes. Returns number of bytes read, or -1 on EOF. */
    suspend fun read(
        target: ByteArray,
        offset: Int = 0,
        byteCount: Int = target.size - offset,
    ): Int {
        if (byteCount == 0) return 0
        if (pending == null) {
            val chunk = recv() ?: return -1
            pending = chunk
            pendingOffset = 0
        }
        val current = pending!!
        val available = current.size - pendingOffset
        val bytesToCopy = minOf(byteCount, available)
        System.arraycopy(current, pendingOffset, target, offset, bytesToCopy)
        pendingOffset += bytesToCopy
        if (pendingOffset >= current.size) {
            pending = null
            pendingOffset = 0
        }
        return bytesToCopy
    }

    /** Reads exactly [target.size] bytes into [target]. Throws EOFException if EOF before full read. */
    suspend fun readFully(target: ByteArray) {
        var readTotal = 0
        while (readTotal < target.size) {
            val count = read(target, readTotal, target.size - readTotal)
            if (count == -1) {
                throw EOFException("Unexpected EOF after reading $readTotal bytes of ${target.size}")
            }
            readTotal += count
        }
    }

    /** Reads all remaining chunks until EOF. */
    suspend fun readToEnd(): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        while (true) {
            val chunk = recv() ?: break
            out.write(chunk)
        }
        return out.toByteArray()
    }

    /** Converts incoming stream byte chunks to Kotlin Flow. */
    fun asFlow(): Flow<ByteArray> =
        flow {
            while (true) {
                val chunk = recv() ?: break
                emit(chunk)
            }
        }

    /**
     * Writes [data] to the stream, chunked into maxPayload-sized packets.
     *
     * Takes ownership of [data]: the caller must not mutate it after calling this,
     * as it may be copied but referenced asynchronously by queued write commands
     * that haven't yet been serialized to the wire.
     */
    suspend fun write(data: ByteArray) {
        check(!closed.get()) { "Cannot write to a closed stream" }
        val stable = data.copyOf()
        var offset = 0
        while (offset < stable.size) {
            val chunkSize = minOf(stable.size - offset, maxPayload)
            flowSemaphore.acquire()
            cmdChannel.send(StreamCmd.Write(localId, remoteId, stable, offset, chunkSize))
            offset += chunkSize
        }
    }

    /** Writes a UTF-8 string to the stream. */
    suspend fun writeUtf8(string: String) {
        write(string.toByteArray(Charsets.UTF_8))
    }

    /** Writes a UTF-8 string followed by a newline (\n). */
    suspend fun writeLine(line: String) {
        writeUtf8("$line\n")
    }

    /** Sends a CLSE packet to close writing. */
    suspend fun closeWrite() {
        if (closed.compareAndSet(false, true)) {
            cmdChannel.trySend(StreamCmd.Close(localId, remoteId))
        }
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            cmdChannel.trySend(StreamCmd.Close(localId, remoteId))
        }
        dataChannel.close()
    }

    internal fun forceCloseNoNotify() {
        closed.set(true)
    }
}
