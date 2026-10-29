package io.github.rhythmcache.adb

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okio.Buffer
import java.util.concurrent.atomic.AtomicBoolean

data class ShellResult(
    val stdout: ByteArray,
    val stderr: ByteArray,
    val exitCode: Int,
) {
    val isSuccess: Boolean get() = exitCode == 0
    val stdoutText: String get() = stdout.toString(Charsets.UTF_8)
    val stderrText: String get() = stderr.toString(Charsets.UTF_8)
}

sealed class ShellChunk {
    data class Stdout(
        val text: String,
    ) : ShellChunk()

    data class Stderr(
        val text: String,
    ) : ShellChunk()

    data class Exit(
        val code: Int,
    ) : ShellChunk()
}

private data class ShellHeader(
    val msgId: Int,
    val len: Int,
)

object AdbShell {
    private const val MAX_SHELL_FRAME_SIZE = 16 * 1024 * 1024 // 16 MB max frame size safety bound

    fun flow(stream: AdbStream): Flow<ShellChunk> =
        kotlinx.coroutines.flow.flow {
            val carry = Buffer()

            while (true) {
                val chunk = stream.recv() ?: break
                carry.write(chunk)

                while (carry.size >= 5) {
                    val header =
                        carry.peek().use { peeker ->
                            val msgId = peeker.readByte().toInt() and 0xFF
                            val len = peeker.readIntLe()
                            ShellHeader(msgId, len)
                        }

                    // Corrupted frame length check: throw explicit Protocol Exception to terminate stream
                    if (header.len !in 0..MAX_SHELL_FRAME_SIZE) {
                        throw AdbException.Protocol("Invalid shell v2 payload length: ${header.len}")
                    }

                    // Incomplete frame: break parser loop to allow stream.recv() to fetch more TCP bytes
                    if (carry.size < 5L + header.len) break

                    carry.skip(5)
                    val data = carry.readByteArray(header.len.toLong())

                    when (header.msgId) {
                        1 -> emit(ShellChunk.Stdout(data.toString(Charsets.UTF_8)))
                        2 -> emit(ShellChunk.Stderr(data.toString(Charsets.UTF_8)))
                        3 -> {
                            val code = data.firstOrNull()?.toInt()?.and(0xFF) ?: 0
                            emit(ShellChunk.Exit(code))
                        }
                    }
                }
            }
        }

    suspend fun collectToResult(stream: AdbStream): ShellResult {
        val stdout = java.io.ByteArrayOutputStream()
        val stderr = java.io.ByteArrayOutputStream()
        var exitCode = 0

        flow(stream).collect { chunk ->
            when (chunk) {
                is ShellChunk.Stdout -> stdout.write(chunk.text.toByteArray(Charsets.UTF_8))
                is ShellChunk.Stderr -> stderr.write(chunk.text.toByteArray(Charsets.UTF_8))
                is ShellChunk.Exit -> exitCode = chunk.code
            }
        }
        return ShellResult(stdout.toByteArray(), stderr.toByteArray(), exitCode)
    }
}

object AdbShellProtocolId {
    const val STDIN: Int = 0
    const val STDOUT: Int = 1
    const val STDERR: Int = 2
    const val EXIT: Int = 3
    const val CLOSE_STDIN: Int = 4
    const val WINDOW_SIZE_CHANGE: Int = 5
}

class AdbInteractiveSession(
    val stream: AdbStream,
) : java.io.Closeable {
    private val writeMutex = Mutex()
    private val _exitCode = CompletableDeferred<Int?>()
    private val isCollected = AtomicBoolean(false)

    /**
     * Completes with the remote shell process exit code, or null if the stream closed without receiving an EXIT packet.
     */
    val exitCode: Deferred<Int?> get() = _exitCode

    /**
     * Returns true if the underlying ADB multiplexed stream is closed.
     */
    val isStreamClosed: Boolean get() = stream.isClosed

    val isClosed: Boolean get() = isStreamClosed

    /**
     * Single-consumer Flow of terminal output bytes (stdout/stderr) from the PTY Shell v2 stream.
     * Can only be collected once per session.
     */
    val outputFlow: Flow<ByteArray> =
        kotlinx.coroutines.flow.flow {
            check(isCollected.compareAndSet(false, true)) {
                "AdbInteractiveSession.outputFlow can only be collected once per session"
            }
            val carry = Buffer()
            try {
                outer@ while (true) {
                    val chunk = stream.recv() ?: break
                    carry.write(chunk)
                    while (carry.size >= 5) {
                        val (msgId, len) =
                            carry.peek().use { peeker ->
                                val id = peeker.readByte().toInt() and 0xFF
                                val l = peeker.readIntLe()
                                Pair(id, l)
                            }

                        if (len < 0 || len > 16 * 1024 * 1024) {
                            throw AdbException.Protocol("Invalid shell frame length: $len")
                        }

                        if (carry.size < 5L + len) break
                        carry.skip(5)
                        val data = carry.readByteArray(len.toLong())

                        when (msgId) {
                            AdbShellProtocolId.STDOUT, AdbShellProtocolId.STDERR -> {
                                emit(data)
                            }
                            AdbShellProtocolId.EXIT -> {
                                if (data.size != 1) {
                                    throw AdbException.Protocol("Invalid shell EXIT packet length: ${data.size}")
                                }
                                val code = data[0].toInt() and 0xFF
                                _exitCode.complete(code)
                                break@outer
                            }
                            else -> {
                                throw AdbException.Protocol("Unknown shell protocol packet id: $msgId")
                            }
                        }
                    }
                }
            } finally {
                if (!_exitCode.isCompleted) {
                    _exitCode.complete(null)
                }
            }
        }


    /**
     * Flow of UTF-8 text chunks from stdout/stderr.
     */
    val textFlow: Flow<String> =
        kotlinx.coroutines.flow.flow {
            outputFlow.collect { bytes ->
                emit(String(bytes, Charsets.UTF_8))
            }
        }

    /**
     * Sends user keystrokes / input data into the interactive shell (Shell v2 msgId = 0).
     */
    suspend fun write(data: ByteArray) {
        if (data.isEmpty()) return
        val header = Buffer().writeByte(AdbShellProtocolId.STDIN).writeIntLe(data.size).readByteArray()
        writeMutex.withLock {
            stream.write(header + data)
        }
    }

    /**
     * Writes a UTF-8 string to device stdin.
     */
    suspend fun writeUtf8(string: String) {
        write(string.toByteArray(Charsets.UTF_8))
    }

    /**
     * Writes a line of text followed by newline.
     */
    suspend fun writeLine(line: String) {
        writeUtf8("$line\n")
    }

    /**
     * Notifies adbd of terminal window dimensions (Shell v2 msgId = 5).
     *
     * AOSP format: "%dx%d,%dx%d\0" (rows x cols, xpixel x ypixel)
     * Triggers ioctl(pty_fd, TIOCSWINSZ) and SIGWINCH on the target device.
     */
    suspend fun resize(
        cols: Int,
        rows: Int,
        xPixel: Int = 0,
        yPixel: Int = 0,
    ) {
        require(cols in 1..65535) { "Columns must be in range 1..65535, got $cols" }
        require(rows in 1..65535) { "Rows must be in range 1..65535, got $rows" }
        val payload = "${rows}x${cols},${xPixel}x${yPixel}\u0000".toByteArray(Charsets.US_ASCII)
        val header = Buffer().writeByte(AdbShellProtocolId.WINDOW_SIZE_CHANGE).writeIntLe(payload.size).readByteArray()
        writeMutex.withLock {
            stream.write(header + payload)
        }
    }

    /**
     * Closes subprocess stdin (Shell v2 msgId = 4).
     */
    suspend fun closeStdin() {
        val header = Buffer().writeByte(AdbShellProtocolId.CLOSE_STDIN).writeIntLe(0).readByteArray()
        writeMutex.withLock {
            stream.write(header)
        }
    }

    override fun close() {
        if (!_exitCode.isCompleted) {
            _exitCode.complete(null)
        }
        stream.close()
    }
}

typealias AdbShellStream = AdbShell

suspend fun AdbConnection.runShell(cmd: String): ShellResult {
    val stream = open("shell,v2,raw:$cmd")
    return try {
        AdbShell.collectToResult(stream)
    } finally {
        stream.close()
    }
}
