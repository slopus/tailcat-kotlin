@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlin.experimental.ExperimentalNativeApi::class)
package io.tailcat.platform

import kotlinx.cinterop.*
import kotlin.native.ref.createCleaner
import platform.posix.*
import platform.linux.inet_pton
import platform.linux.ifaddrs
import platform.linux.getifaddrs
import platform.linux.freeifaddrs

private class LockStorage {
    val mutex = nativeHeap.alloc<pthread_mutex_t>().ptr
    val condition = nativeHeap.alloc<pthread_cond_t>().ptr
    init {
        check(pthread_mutex_init(mutex, null) == 0)
        memScoped {
            val attr = alloc<pthread_condattr_t>(); check(pthread_condattr_init(attr.ptr) == 0)
            try { check(pthread_condattr_setclock(attr.ptr, CLOCK_MONOTONIC) == 0); check(pthread_cond_init(condition, attr.ptr) == 0) }
            finally { pthread_condattr_destroy(attr.ptr) }
        }
    }
    fun dispose() { pthread_cond_destroy(condition); pthread_mutex_destroy(mutex); nativeHeap.free(condition); nativeHeap.free(mutex) }
}
internal actual class PlatformLock actual constructor() {
    private val storage = LockStorage()
    @Suppress("unused") private val cleaner = createCleaner(storage) { it.dispose() }
    actual fun lock() { check(pthread_mutex_lock(storage.mutex) == 0) }
    actual fun unlock() { check(pthread_mutex_unlock(storage.mutex) == 0) }
    actual fun signalAll() { check(pthread_cond_broadcast(storage.condition) == 0) }
    actual fun await(timeoutMillis: Long) {
        val result = if (timeoutMillis <= 0) pthread_cond_wait(storage.condition, storage.mutex) else memScoped {
            val time = alloc<timespec>(); check(clock_gettime(CLOCK_MONOTONIC, time.ptr) == 0)
            val nanos = time.tv_nsec + (timeoutMillis % 1000) * 1_000_000
            time.tv_sec += timeoutMillis / 1000 + nanos / 1_000_000_000; time.tv_nsec = nanos % 1_000_000_000
            pthread_cond_timedwait(storage.condition, storage.mutex, time.ptr)
        }
        check(result == 0 || result == ETIMEDOUT)
    }
}
internal class NativeThreadState(val name: String, val block: () -> Unit) { val condition = PlatformLock(); var completed = false }
internal actual class PlatformThread internal constructor(private val state: NativeThreadState) {
    actual fun join(timeoutMillis: Long) {
        require(timeoutMillis >= 0); val deadline = monotonicMillis() + timeoutMillis
        state.condition.withLock {
            while (!state.completed) {
                val remaining = if (timeoutMillis == 0L) 0L else deadline - monotonicMillis()
                if (timeoutMillis != 0L && remaining <= 0) return
                state.condition.await(remaining)
            }
        }
    }
}
internal actual fun startThread(name: String, block: () -> Unit): PlatformThread {
    val state = NativeThreadState(name, block); val reference = StableRef.create(state)
    val result = memScoped {
        val thread = alloc<pthread_tVar>()
        val code = pthread_create(thread.ptr, null, staticCFunction { pointer ->
            val ref = pointer!!.asStableRef<NativeThreadState>(); val work = ref.get()
            try { work.block() } catch (error: Throwable) { error.printStackTrace() }
            finally { work.condition.withLock { work.completed = true; work.condition.signalAll() }; ref.dispose() }
            null
        }, reference.asCPointer())
        if (code == 0) pthread_detach(thread.value)
        code
    }
    if (result != 0) { reference.dispose(); error("pthread_create: $result") }
    return PlatformThread(state)
}
private fun clockMillis(clock: clockid_t): Long = memScoped {
    val time = alloc<timespec>(); check(clock_gettime(clock, time.ptr) == 0); time.tv_sec * 1000 + time.tv_nsec / 1_000_000
}
internal actual fun monotonicMillis(): Long = clockMillis(CLOCK_MONOTONIC)
internal actual fun wallClockMillis(): Long = clockMillis(CLOCK_REALTIME)
internal actual fun platformSleep(millis: Long) {
    require(millis >= 0)
    memScoped {
        val request = alloc<timespec>(); val remainder = alloc<timespec>()
        request.tv_sec = millis / 1000; request.tv_nsec = millis % 1000 * 1_000_000
        while (nanosleep(request.ptr, remainder.ptr) != 0) {
            if (errno != EINTR) error("nanosleep: $errno")
            request.tv_sec = remainder.tv_sec; request.tv_nsec = remainder.tv_nsec
        }
    }
}
internal actual fun secureRandom(count: Int): ByteArray {
    require(count >= 0); if (count == 0) return byteArrayOf()
    val fd = open("/dev/urandom", O_RDONLY or O_CLOEXEC); check(fd >= 0) { "Opening system random: $errno" }
    try {
        return ByteArray(count).also { bytes -> bytes.usePinned { pinned ->
            var offset = 0
            while (offset < bytes.size) {
                val n = read(fd, pinned.addressOf(offset), (bytes.size - offset).convert())
                if (n < 0 && errno == EINTR) continue
                check(n > 0) { "Reading system random: $errno" }; offset += n.toInt()
            }
        } }
    } finally { close(fd) }
}
internal data class NativeAddress(val family: Int, val bytes: ByteArray)
private fun numericAddress(host: String, port: Int, family: Int): NativeAddress? = memScoped {
    if (family == AF_UNSPEC || family == AF_INET) {
        val address = alloc<sockaddr_in>(); memset(address.ptr, 0, sizeOf<sockaddr_in>().convert())
        address.sin_family = AF_INET.convert(); address.sin_port = htons(port.toUShort())
        if (inet_pton(AF_INET, host, address.sin_addr.ptr) == 1) return NativeAddress(AF_INET, address.ptr.readBytes(sizeOf<sockaddr_in>().toInt()))
    }
    if (family == AF_UNSPEC || family == AF_INET6) {
        val address = alloc<sockaddr_in6>(); memset(address.ptr, 0, sizeOf<sockaddr_in6>().convert())
        address.sin6_family = AF_INET6.convert(); address.sin6_port = htons(port.toUShort())
        if (inet_pton(AF_INET6, host, address.sin6_addr.ptr) == 1) return NativeAddress(AF_INET6, address.ptr.readBytes(sizeOf<sockaddr_in6>().toInt()))
    }
    null
}
private fun systemResolve(host: String, port: Int, type: Int, family: Int): List<NativeAddress> = memScoped {
    val hints = alloc<addrinfo>(); memset(hints.ptr, 0, sizeOf<addrinfo>().convert()); hints.ai_family = family; hints.ai_socktype = type
    val result = alloc<CPointerVar<addrinfo>>(); val code = getaddrinfo(host, port.toString(), hints.ptr, result.ptr)
    check(code == 0) { "DNS $host: ${gai_strerror(code)?.toKString()}" }
    try {
        val addresses = mutableListOf<NativeAddress>(); var current = result.value
        while (current != null) {
            val entry = current.pointed
            if (entry.ai_family == AF_INET || entry.ai_family == AF_INET6) entry.ai_addr?.let { addresses += NativeAddress(entry.ai_family, it.readBytes(entry.ai_addrlen.toInt())) }
            current = entry.ai_next
        }
        addresses
    } finally { freeaddrinfo(result.value) }
}
private class ResolveJob(val host: String, val port: Int, val type: Int, val family: Int) {
    val condition = PlatformLock(); var done = false; var addresses = emptyList<NativeAddress>(); var failure: Throwable? = null
}
private object NativeResolver {
    private val condition = PlatformLock(); private val queue = ArrayDeque<ResolveJob>()
    @Suppress("unused") private val workers = List(2) { index -> startThread("tailcat-dns-$index") {
        while (true) {
            val job = condition.withLock { while (queue.isEmpty()) condition.await(0); queue.removeFirst() }
            var result = emptyList<NativeAddress>(); var failure: Throwable? = null
            try { result = systemResolve(job.host, job.port, job.type, job.family) } catch (error: Throwable) { failure = error }
            job.condition.withLock { job.addresses = result; job.failure = failure; job.done = true; job.condition.signalAll() }
        }
    } }
    fun enqueue(job: ResolveJob) = condition.withLock { check(queue.size < 64) { "DNS queue full" }; queue.addLast(job); condition.signalAll() }
    fun cancel(job: ResolveJob) = condition.withLock { queue.remove(job) }
}
internal fun nativeResolve(host: String, port: Int, type: Int, family: Int = AF_UNSPEC,
    deadline: Long = monotonicMillis() + 10000, ensureOpen: () -> Unit = {}): List<NativeAddress> {
    numericAddress(host, port, family)?.let { return listOf(it) }
    val job = ResolveJob(host, port, type, family); NativeResolver.enqueue(job)
    try {
        while (true) {
            ensureOpen()
            job.condition.withLock {
                if (job.done) { job.failure?.let { throw it }; return job.addresses }
                val remaining = deadline - monotonicMillis(); check(remaining > 0) { "DNS timed out" }; job.condition.await(remaining.coerceAtMost(100))
            }
        }
    } finally { NativeResolver.cancel(job) }
}
internal fun nativeEndpoint(address: CPointer<sockaddr>, size: UInt): Endpoint = memScoped {
    val host = allocArray<ByteVar>(1025); val service = allocArray<ByteVar>(32)
    val result = getnameinfo(address, size, host, 1025u, service, 32u, NI_NUMERICHOST or NI_NUMERICSERV); check(result == 0) { "getnameinfo: $result" }
    Endpoint(host.toKString().removePrefix("::ffff:"), service.toKString().toInt())
}
internal actual fun resolveHost(host: String): List<String> = nativeResolve(host, 0, SOCK_STREAM).map { address ->
    address.bytes.usePinned { nativeEndpoint(it.addressOf(0).reinterpret(), address.bytes.size.toUInt()).host }
}.distinct()
internal actual fun localAddresses(): List<String> = memScoped {
    val list = alloc<CPointerVar<ifaddrs>>(); check(getifaddrs(list.ptr) == 0) { "getifaddrs: $errno" }
    try {
        val addresses = mutableListOf<String>(); var current = list.value
        while (current != null) {
            val entry = current.pointed; current = entry.ifa_next
            if (entry.ifa_flags and IFF_UP.toUInt() == 0u || entry.ifa_flags and IFF_LOOPBACK.toUInt() != 0u) continue
            val pointer = entry.ifa_addr ?: continue; val family = pointer.pointed.sa_family.toInt()
            val size = when (family) { AF_INET -> sizeOf<sockaddr_in>(); AF_INET6 -> sizeOf<sockaddr_in6>(); else -> continue }
            val host = nativeEndpoint(pointer, size.toUInt()).host
            if ('%' !in host && !host.startsWith("fe80:") && !host.startsWith("ff") && host != "0.0.0.0" && host != "::") addresses += host
        }
        addresses.distinct()
    } finally { freeifaddrs(list.value) }
}
