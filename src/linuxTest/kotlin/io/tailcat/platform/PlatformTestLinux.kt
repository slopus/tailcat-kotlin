@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
package io.tailcat.platform

import kotlinx.cinterop.*
import platform.posix.*

internal actual fun platformTestEnv(name: String): String? = getenv(name)?.toKString()
internal actual class TestListener actual constructor() {
    private val lock = PlatformLock(); private var closed = false; private var client = -1
    private val descriptor = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
    actual val port: Int
    init {
        check(descriptor >= 0)
        memScoped {
            val address = alloc<sockaddr_in>(); memset(address.ptr,0,sizeOf<sockaddr_in>().convert()); address.sin_family = AF_INET.convert(); address.sin_addr.s_addr = htonl(0x7f000001u)
            check(bind(descriptor,address.ptr.reinterpret(),sizeOf<sockaddr_in>().toUInt()) == 0); check(listen(descriptor,4) == 0); check(fcntl(descriptor,F_SETFL,O_NONBLOCK) == 0)
            val size = alloc<socklen_tVar>(); size.value = sizeOf<sockaddr_in>().toUInt(); check(getsockname(descriptor,address.ptr.reinterpret(),size.ptr) == 0); port = ntohs(address.sin_port).toInt()
        }
    }
    private val worker = startThread("test-listener") {
        memScoped {
            val item = alloc<pollfd>(); item.fd = descriptor; item.events = POLLIN.convert()
            while (!lock.withLock { closed }) {
                if (poll(item.ptr,1u,100) <= 0) continue
                val accepted = accept(descriptor,null,null); if (accepted < 0) continue
                lock.withLock { if (closed) platform.posix.close(accepted) else client = accepted; lock.signalAll() }; return@startThread
            }
        }
    }
    actual fun awaitAccepted(timeoutMillis: Long): Boolean = lock.withLock {
        val deadline = monotonicMillis()+timeoutMillis
        while (client < 0 && !closed) { val remaining = deadline-monotonicMillis(); if (remaining <= 0) return false; lock.await(remaining) }; client >= 0
    }
    actual fun close() {
        val wasClosed = lock.withLock {
            val previous = closed; closed = true; if (client >= 0) { shutdown(client,SHUT_RDWR); platform.posix.close(client); client = -1 }; lock.signalAll(); previous
        }
        if (!wasClosed) { shutdown(descriptor,SHUT_RDWR); worker.join(1000); platform.posix.close(descriptor) }
    }
}
