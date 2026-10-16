@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
package io.tailcat.platform

import io.tailcat.openssl.*
import kotlinx.cinterop.*
import platform.posix.*
import platform.linux.inet_pton

private fun nonblocking(fd: Int) {
    val flags = fcntl(fd, F_GETFL); check(flags >= 0 && fcntl(fd, F_SETFL, flags or O_NONBLOCK) == 0) { "fcntl: $errno" }
}
private fun ready(fd: Int, events: Int, deadline: Long?, ensureOpen: () -> Unit): Boolean = memScoped {
    val item = alloc<pollfd>(); item.fd = fd; item.events = events.convert()
    while (true) {
        ensureOpen(); val remaining = deadline?.minus(monotonicMillis()); if (remaining != null && remaining <= 0) return false
        item.revents = 0; val result = poll(item.ptr, 1u, (remaining?.coerceAtMost(250) ?: 250).toInt())
        if (result < 0) { if (errno == EINTR) continue; error("poll: $errno") }
        if (result == 0) continue
        check(item.revents.toInt() and POLLNVAL == 0) { "Invalid socket" }; return true
    }
    @Suppress("UNREACHABLE_CODE") false
}
private fun socketAddress(address: NativeAddress, block: (CPointer<sockaddr>, UInt) -> Unit) {
    address.bytes.usePinned { block(it.addressOf(0).reinterpret(), address.bytes.size.toUInt()) }
}
internal actual class PlatformUdp actual constructor(bindPort: Int, private val ipv6: Boolean) {
    private val state = PlatformLock(); private val receiveLock = PlatformLock(); private val receiveBuffer = ByteArray(65536)
    private var descriptor = -1; private var active = 0; private var closed = false
    actual val localPort: Int
    init {
        require(bindPort in 0..65535); val family = if (ipv6) AF_INET6 else AF_INET
        descriptor = socket(family, SOCK_DGRAM, IPPROTO_UDP); check(descriptor >= 0) { "UDP socket: $errno" }
        try {
            nonblocking(descriptor)
            memScoped {
                if (ipv6) { val enabled = alloc<IntVar>(); enabled.value = 1; check(setsockopt(descriptor, IPPROTO_IPV6, IPV6_V6ONLY, enabled.ptr, sizeOf<IntVar>().toUInt()) == 0) }
                val address = nativeResolve(if (ipv6) "::" else "0.0.0.0", bindPort, SOCK_DGRAM, family).first()
                socketAddress(address) { pointer, size -> check(bind(descriptor, pointer, size) == 0) { "UDP bind: $errno" } }
                val storage = alloc<sockaddr_storage>(); val size = alloc<socklen_tVar>(); size.value = sizeOf<sockaddr_storage>().toUInt()
                check(getsockname(descriptor, storage.ptr.reinterpret(), size.ptr) == 0); localPort = nativeEndpoint(storage.ptr.reinterpret(), size.value).port
            }
        } catch (error: Throwable) { platform.posix.close(descriptor); descriptor = -1; throw error }
    }
    private fun ensureOpen() = state.withLock { check(!closed) { "UDP socket closed" } }
    private fun claim(): Int = state.withLock { check(!closed && descriptor >= 0) { "UDP socket closed" }; active++; descriptor }
    private fun release() = state.withLock { active--; if (closed && active == 0 && descriptor >= 0) { platform.posix.close(descriptor); descriptor = -1 } }
    actual fun send(destination: Endpoint, data: ByteArray) {
        require(data.size <= 65507 && destination.port != 0); val fd = claim()
        try {
            val deadline = monotonicMillis() + 10000
            val address = nativeResolve(destination.host, destination.port, SOCK_DGRAM, if (ipv6) AF_INET6 else AF_INET, deadline, ::ensureOpen).first()
            data.usePinned { payload -> address.bytes.usePinned { target ->
                while (true) {
                    ensureOpen()
                    val result = sendto(fd, if (data.isEmpty()) null else payload.addressOf(0), data.size.convert(), MSG_NOSIGNAL, target.addressOf(0).reinterpret(), address.bytes.size.toUInt())
                    if (result == data.size.toLong()) return
                    if (result < 0 && errno == EINTR) continue
                    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { check(ready(fd, POLLOUT, deadline, ::ensureOpen)) { "UDP send timed out" }; continue }
                    error("UDP send: $errno")
                }
            } }
        } finally { release() }
    }
    actual fun receive(timeoutMillis: Int): RawDatagram? {
        require(timeoutMillis >= 0); receiveLock.lock()
        try {
            val fd = claim()
            try {
                val deadline = if (timeoutMillis == 0) null else monotonicMillis() + timeoutMillis
                return memScoped {
                    val address = alloc<sockaddr_storage>(); val size = alloc<socklen_tVar>()
                    receiveBuffer.usePinned { payload ->
                        while (true) {
                            if (!ready(fd, POLLIN, deadline, ::ensureOpen)) return null
                            size.value = sizeOf<sockaddr_storage>().toUInt()
                            val count = recvfrom(fd, payload.addressOf(0), receiveBuffer.size.convert(), 0, address.ptr.reinterpret(), size.ptr)
                            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue
                            check(count >= 0) { "UDP receive: $errno" }
                            return RawDatagram(nativeEndpoint(address.ptr.reinterpret(), size.value), receiveBuffer.copyOf(count.toInt()))
                        }
                        @Suppress("UNREACHABLE_CODE") null
                    }
                }
            } finally { release() }
        } finally { receiveLock.unlock() }
    }
    actual fun close() = state.withLock {
        if (closed) return
        closed = true; if (descriptor >= 0) shutdown(descriptor, SHUT_RDWR)
        if (active == 0 && descriptor >= 0) { platform.posix.close(descriptor); descriptor = -1 }
    }
}
private data class StreamLease(val descriptor: Int, val ssl: CPointer<SSL>?)
private data class TLSResult(val count: Int, val error: Int, val systemError: Int, val description: String)
private fun opensslErrors(): String = memScoped {
    val messages = mutableListOf<String>(); val buffer = allocArray<ByteVar>(256)
    while (true) { val code = ERR_get_error(); if (code == 0uL) break; ERR_error_string_n(code, buffer, 256u); messages += buffer.toKString() }
    messages.joinToString("; ")
}
private fun numericIP(host: String): Boolean = memScoped { val storage = alloc<in6_addr>(); inet_pton(AF_INET, host, storage.ptr) == 1 || inet_pton(AF_INET6, host, storage.ptr) == 1 }
private fun <T> withoutSigpipe(block: () -> T): T = memScoped {
    val mask = alloc<sigset_t>(); val previous = alloc<sigset_t>(); val pending = alloc<sigset_t>()
    sigemptyset(mask.ptr); sigaddset(mask.ptr, SIGPIPE); check(pthread_sigmask(SIG_BLOCK, mask.ptr, previous.ptr) == 0)
    check(sigpending(pending.ptr) == 0); val alreadyPending = sigismember(pending.ptr, SIGPIPE) == 1
    try { block() } finally {
        if (!alreadyPending && sigpending(pending.ptr) == 0 && sigismember(pending.ptr, SIGPIPE) == 1) { val received = alloc<IntVar>(); sigwait(mask.ptr, received.ptr) }
        pthread_sigmask(SIG_SETMASK, previous.ptr, null)
    }
}
internal actual class PlatformStream actual constructor() {
    private val state = PlatformLock(); private val connectLock = PlatformLock(); private val readLock = PlatformLock(); private val writeLock = PlatformLock(); private val sslLock = PlatformLock()
    private var descriptor = -1; private var context: CPointer<SSL_CTX>? = null; private var ssl: CPointer<SSL>? = null
    private var connected = false; private var closed = false; private var active = 0
    private fun ensureOpen() = state.withLock { check(!closed) { "Stream closed" } }
    private fun dispose() { ssl?.let(::SSL_free); ssl = null; context?.let(::SSL_CTX_free); context = null; if (descriptor >= 0) platform.posix.close(descriptor); descriptor = -1 }
    private fun release() = state.withLock { active--; if (closed && active == 0) dispose() }
    private fun claim(): StreamLease = state.withLock { check(!closed && connected && descriptor >= 0) { "Stream not connected or closed" }; active++; StreamLease(descriptor, ssl) }
    private fun tlsOperation(connection: CPointer<SSL>, operation: () -> Int): TLSResult = sslLock.withLock {
        withoutSigpipe {
            ERR_clear_error(); val count = operation(); val osError = errno; val code = if (count <= 0) SSL_get_error(connection, count) else 0
            val description = if (code != 0 && code != 2 && code != 3) opensslErrors() else ""
            TLSResult(count, code, osError, description)
        }
    }
    actual fun connect(host: String, port: Int, tls: Boolean, serverName: String, certificateName: String, timeoutMillis: Int, insecureForTests: Boolean) {
        require(port in 1..65535 && timeoutMillis > 0); connectLock.lock()
        try {
            state.withLock { check(!closed && !connected && active == 0); active++ }
            try {
                val deadline = monotonicMillis() + timeoutMillis
                val addresses = nativeResolve(host, port, SOCK_STREAM, deadline = deadline, ensureOpen = ::ensureOpen)
                var lastFailure: Throwable? = null; var established = false
                for (address in addresses) {
                    ensureOpen(); val fd = socket(address.family, SOCK_STREAM, IPPROTO_TCP); check(fd >= 0) { "TCP socket: $errno" }
                    state.withLock { descriptor = fd }
                    try {
                        ensureOpen(); nonblocking(fd)
                        memScoped { val enabled = alloc<IntVar>(); enabled.value = 1; check(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, enabled.ptr, sizeOf<IntVar>().toUInt()) == 0) }
                        var result = 0; socketAddress(address) { pointer, size -> result = platform.posix.connect(fd, pointer, size) }
                        if (result != 0) {
                            check(errno == EINPROGRESS || errno == EALREADY || errno == EINTR) { "TCP connect: $errno" }
                            val attemptDeadline = if (addresses.size > 1) minOf(deadline, monotonicMillis() + 3000) else deadline
                            check(ready(fd, POLLOUT, attemptDeadline, ::ensureOpen)) { "TCP connect timed out" }
                            memScoped {
                                val error = alloc<IntVar>(); val size = alloc<socklen_tVar>(); size.value = sizeOf<IntVar>().toUInt()
                                check(getsockopt(fd, SOL_SOCKET, SO_ERROR, error.ptr, size.ptr) == 0 && error.value == 0) { "TCP connect: ${error.value}" }
                            }
                        }
                        established = true; break
                    } catch (error: Throwable) {
                        lastFailure = error; state.withLock { if (descriptor == fd) { platform.posix.close(fd); descriptor = -1 } }; ensureOpen()
                    }
                }
                if (!established) throw (lastFailure ?: IllegalStateException("No address for $host"))
                if (tls) {
                    val createdContext = SSL_CTX_new(TLS_client_method()) ?: error("SSL_CTX_new: ${opensslErrors()}")
                    state.withLock { context = createdContext }
                    if (!insecureForTests) check(SSL_CTX_set_default_verify_paths(createdContext) == 1) { "Loading TLS trust: ${opensslErrors()}" }
                    SSL_CTX_set_verify(createdContext, if (insecureForTests) 0 else 1, null)
                    check(SSL_CTX_ctrl(createdContext, 123, 0x0303, null) == 1L) { "Setting TLS minimum version" }
                    val connection = SSL_new(createdContext) ?: error("SSL_new: ${opensslErrors()}"); state.withLock { ssl = connection }
                    check(SSL_set_fd(connection, descriptor) == 1); SSL_ctrl(connection, 33, 3, null)
                    if (!numericIP(serverName)) memScoped { check(SSL_ctrl(connection, 55, 0, serverName.cstr.ptr) == 1L) { "Setting TLS SNI" } }
                    if (!insecureForTests) {
                        val verification = SSL_get0_param(connection) ?: error("TLS verification parameters unavailable")
                        X509_VERIFY_PARAM_set_hostflags(verification, 4u)
                        val verified = if (numericIP(certificateName)) X509_VERIFY_PARAM_set1_ip_asc(verification, certificateName) else X509_VERIFY_PARAM_set1_host(verification, certificateName, 0u)
                        check(verified == 1) { "Setting TLS certificate name" }
                    }
                    while (true) {
                        ensureOpen(); val result = tlsOperation(connection) { SSL_connect(connection) }; if (result.count == 1) break
                        if (result.error == 2 || result.error == 3) check(ready(descriptor, if (result.error == 2) POLLIN else POLLOUT, deadline, ::ensureOpen)) { "TLS handshake timed out" }
                        else if (result.error == 5 && result.systemError == EINTR) continue
                        else error("TLS handshake: ${result.description} (SSL ${result.error}, errno ${result.systemError})")
                    }
                    if (!insecureForTests) check(SSL_get_verify_result(connection) == 0L) { "TLS certificate verification failed" }
                }
                state.withLock { check(!closed) { "Stream closed" }; connected = true }
            } catch (error: Throwable) { close(); throw error } finally { release() }
        } finally { connectLock.unlock() }
    }
    private fun bounds(buffer: ByteArray, offset: Int, length: Int) { require(length >= 0 && offset >= 0 && length <= buffer.size && offset <= buffer.size - length) }
    actual fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        bounds(buffer, offset, length); if (length == 0) return 0; readLock.lock()
        try {
            val lease = claim()
            try { return buffer.usePinned { pinned ->
                while (true) {
                    ensureOpen()
                    if (lease.ssl == null) {
                        val count = recv(lease.descriptor, pinned.addressOf(offset), length.convert(), 0)
                        if (count > 0) return count.toInt(); if (count == 0L) return -1; if (errno == EINTR) continue
                        check(errno == EAGAIN || errno == EWOULDBLOCK) { "TCP read: $errno" }; ready(lease.descriptor, POLLIN, null, ::ensureOpen)
                    } else {
                        val result = tlsOperation(lease.ssl) { SSL_read(lease.ssl, pinned.addressOf(offset), length) }
                        if (result.count > 0) return result.count; if (result.error == 6) return -1; if (result.error == 5 && result.systemError == EINTR) continue
                        check(result.error == 2 || result.error == 3) { "TLS read: ${result.description} (SSL ${result.error}, errno ${result.systemError})" }
                        ready(lease.descriptor, if (result.error == 2) POLLIN else POLLOUT, null, ::ensureOpen)
                    }
                }
                @Suppress("UNREACHABLE_CODE") -1
            } } finally { release() }
        } finally { readLock.unlock() }
    }
    actual fun write(buffer: ByteArray, offset: Int, length: Int) {
        bounds(buffer, offset, length); writeLock.lock()
        try {
            val lease = claim()
            try { if (length > 0) buffer.usePinned { pinned ->
                var sent = 0
                while (sent < length) {
                    ensureOpen()
                    if (lease.ssl == null) {
                        val count = send(lease.descriptor, pinned.addressOf(offset + sent), (length - sent).convert(), MSG_NOSIGNAL)
                        if (count > 0) { sent += count.toInt(); continue }; if (count < 0 && errno == EINTR) continue
                        check(count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { "TCP write: $errno" }; ready(lease.descriptor, POLLOUT, null, ::ensureOpen)
                    } else {
                        val result = tlsOperation(lease.ssl) { SSL_write(lease.ssl, pinned.addressOf(offset + sent), length - sent) }
                        if (result.count > 0) { sent += result.count; continue }; if (result.error == 5 && result.systemError == EINTR) continue
                        check(result.error == 2 || result.error == 3) { "TLS write: ${result.description} (SSL ${result.error}, errno ${result.systemError})" }
                        ready(lease.descriptor, if (result.error == 2) POLLIN else POLLOUT, null, ::ensureOpen)
                    }
                }
            } } finally { release() }
        } finally { writeLock.unlock() }
    }
    actual fun close() = state.withLock { if (closed) return; closed = true; connected = false; if (descriptor >= 0) shutdown(descriptor, SHUT_RDWR); if (active == 0) dispose() }
}
