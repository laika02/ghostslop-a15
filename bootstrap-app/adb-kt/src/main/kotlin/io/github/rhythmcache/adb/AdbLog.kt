package io.github.rhythmcache.adb

import java.util.logging.Level
import java.util.logging.Logger

/**
 * Lightweight internal logger for adb-kt using standard java.util.logging.
 * Automatically forwards to logcat on Android and stderr/handlers on desktop JVM.
 */
internal object AdbLog {
    private val logger = Logger.getLogger("adb-kt")

    fun d(tag: String, msg: String) {
        logger.log(Level.FINE, "[$tag] $msg")
    }

    fun i(tag: String, msg: String) {
        logger.log(Level.INFO, "[$tag] $msg")
    }

    fun w(tag: String, msg: String) {
        logger.log(Level.WARNING, "[$tag] $msg")
    }

    fun e(tag: String, msg: String, throwable: Throwable? = null) {
        logger.log(Level.SEVERE, "[$tag] $msg", throwable)
    }
}
