package io.github.rhythmcache.adb.pairing

/**
 * Persists paired-device identity: after a successful pairing exchange, the
 * peer's certificate must be pinned for all future TLS transport
 * connections to that device (pairing's "accept any cert" is only safe
 * because SPAKE2 authenticates the session on top of it -- the transport
 * connection has no such secondary check, so it MUST validate against a
 * previously-pinned cert).
 *
 * No default implementation is provided since storage is inherently
 * platform-specific (file-based on JVM/desktop, Room/SharedPreferences on
 * Android, etc.) -- implement this in your application layer.
 */
interface PairedDeviceStore {
    /** Persists [certPem] under [guid], overwriting any existing entry. */
    suspend fun save(
        guid: String,
        certPem: String,
    )

    /** Returns the pinned certificate PEM for [guid], or null if not paired. */
    suspend fun getCert(guid: String): String?

    suspend fun remove(guid: String)

    suspend fun listPaired(): List<String>
}
