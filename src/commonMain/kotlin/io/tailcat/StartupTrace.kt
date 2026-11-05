package io.tailcat

import io.tailcat.platform.PlatformLock
import io.tailcat.platform.monotonicMillis
import io.tailcat.platform.withLock

/** Internal, opt-in benchmark diagnostics. No callbacks, secrets, or process-global observer. */
internal class StartupTrace {
    internal data class Event(val name: String, val atMillis: Long, val value: Long?)
    private val lock = PlatformLock()
    private val started = monotonicMillis()
    private val events = ArrayList<Event>()
    private val once = mutableSetOf<String>()
    fun mark(name: String, value: Long? = null) = lock.withLock {
        if (events.size < 128) events.add(Event(name, monotonicMillis() - started, value))
    }
    fun markOnce(name: String, value: Long? = null) = lock.withLock {
        if (events.size < 128 && once.add(name)) events.add(Event(name, monotonicMillis() - started, value))
    }
    fun snapshot(): List<Event> = lock.withLock { events.toList() }
}