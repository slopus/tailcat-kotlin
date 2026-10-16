package io.tailcat.platform

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate
import javax.net.ssl.SSLPeerUnverifiedException
import java.net.IDN
import java.util.Locale
import io.tailcat.IpAddress

internal actual class PlatformLock actual constructor() {
    private val mutex = ReentrantLock()
    private val condition = mutex.newCondition()
    actual fun lock() = mutex.lock()
    actual fun unlock() = mutex.unlock()
    actual fun await(timeoutMillis: Long) {
        if (timeoutMillis <= 0) condition.await() else condition.await(timeoutMillis, TimeUnit.MILLISECONDS)
    }
    actual fun signalAll() = condition.signalAll()
}
internal actual class PlatformThread internal constructor(private val thread: Thread) {
    actual fun join(timeoutMillis: Long) { require(timeoutMillis >= 0); if (Thread.currentThread() !== thread) thread.join(timeoutMillis) }
}
internal actual fun startThread(name: String, block: () -> Unit): PlatformThread = PlatformThread(Thread(block, name).apply { isDaemon = true; start() })
internal actual fun monotonicMillis(): Long = System.nanoTime() / 1_000_000L
internal actual fun wallClockMillis(): Long = System.currentTimeMillis()
private val random = SecureRandom()
private val tlsInitializer = ThreadPoolExecutor(1,1,0L,TimeUnit.MILLISECONDS,ArrayBlockingQueue<Runnable>(2),
    { task -> Thread(task,"tailcat-tls-init").apply { isDaemon = true } },ThreadPoolExecutor.AbortPolicy())
private fun prepareFactory(factory: SSLSocketFactory): SSLSocketFactory { factory.createSocket().close(); return factory }
private val verifiedFactory by lazy { tlsInitializer.submit<SSLSocketFactory> { prepareFactory(SSLSocketFactory.getDefault() as SSLSocketFactory) } }
private val insecureTestFactory by lazy { tlsInitializer.submit<SSLSocketFactory> {
    val trust = object : X509TrustManager {
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
    }
    prepareFactory(SSLContext.getInstance("TLS").apply { init(null,arrayOf(trust),random) }.socketFactory)
} }
internal actual fun secureRandom(count: Int): ByteArray { require(count >= 0); return ByteArray(count).also(random::nextBytes) }
internal actual fun platformSleep(millis: Long) { require(millis >= 0); Thread.sleep(millis) }
private fun InetAddress.numeric(): String = if (address.size == 4) IpAddress.format4(address) else IpAddress.format6(address)
internal actual fun resolveHost(host: String): List<String> {
    val pending = resolver.submit<Array<InetAddress>> { InetAddress.getAllByName(host) }
    try { return pending.get(10,TimeUnit.SECONDS).map { it.numeric() }.distinct() }
    finally { pending.cancel(false); resolver.purge() }
}
internal actual fun localAddresses(): List<String> = Collections.list(NetworkInterface.getNetworkInterfaces())
    .filter { it.isUp && !it.isLoopback }.flatMap { Collections.list(it.inetAddresses) }
    .filter { !it.isAnyLocalAddress && !it.isLoopbackAddress && !it.isLinkLocalAddress && !it.isMulticastAddress }.map { it.numeric() }.distinct()

internal actual class PlatformUdp actual constructor(bindPort: Int, ipv6: Boolean) {
    private val socket = DatagramSocket(null)
    private val receiveLock = ReentrantLock()
    private val receiveBuffer = ByteArray(65536)
    actual val localPort: Int
    init {
        require(bindPort in 0..65535)
        try { socket.bind(InetSocketAddress(InetAddress.getByName(if (ipv6) "::" else "0.0.0.0"), bindPort)); localPort = socket.localPort }
        catch (error: Throwable) { socket.close(); throw error }
    }
    actual fun send(destination: Endpoint, data: ByteArray) {
        require(data.size <= 65507 && destination.port != 0)
        socket.send(DatagramPacket(data, data.size, InetAddress.getByName(destination.host), destination.port))
    }
    actual fun receive(timeoutMillis: Int): RawDatagram? {
        require(timeoutMillis >= 0); receiveLock.lock()
        try {
            socket.soTimeout = timeoutMillis
            val packet = DatagramPacket(receiveBuffer, receiveBuffer.size)
            return try { socket.receive(packet); RawDatagram(Endpoint(packet.address.numeric(), packet.port), packet.data.copyOfRange(packet.offset, packet.offset + packet.length)) }
            catch (_: SocketTimeoutException) { null }
        } finally { receiveLock.unlock() }
    }
    actual fun close() = socket.close()
}

private val resolver = ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS,
    ArrayBlockingQueue<Runnable>(64), { task -> Thread(task, "tailcat-dns").apply { isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
private fun verifyOverrideName(socket: SSLSocket, name: String) {
    val certificate = socket.session.peerCertificates.firstOrNull() as? X509Certificate ?: throw SSLPeerUnverifiedException("No server certificate")
    val alternatives = certificate.subjectAlternativeNames.orEmpty()
    val ip = ':' in name || name.isNotEmpty() && name.all { it in '0'..'9' || it == '.' }
    val matches = if (ip) {
        val expected = InetAddress.getByName(name).address
        alternatives.any { entry ->
            if (entry.size < 2 || entry[0] != 7) false else {
                val address = entry[1] as? String
                address != null && (':' in address || address.isNotEmpty() && address.all { it in '0'..'9' || it == '.' }) && InetAddress.getByName(address).address.contentEquals(expected)
            }
        }
    } else {
        val expected = IDN.toASCII(name.removeSuffix("."),IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
        alternatives.any { entry ->
            if (entry.size < 2 || entry[0] != 2) false else {
                val pattern = entry[1] as? String ?: return@any false
                val wildcard = pattern.startsWith("*.")
                val suffix = IDN.toASCII((if (wildcard) pattern.substring(2) else pattern).removeSuffix("."),IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
                if (!wildcard) expected == suffix else '.' in suffix && expected.endsWith(".$suffix") && expected.removeSuffix(".$suffix").let { it.isNotEmpty() && '.' !in it }
            }
        }
    }
    if (!matches) throw SSLPeerUnverifiedException("Certificate does not identify $name")
}
internal actual class PlatformStream actual constructor() {
    private val state = Any()
    private val connectLock = ReentrantLock()
    private val readLock = ReentrantLock()
    private val writeLock = ReentrantLock()
    @Volatile private var closed = false
    private var socket: Socket? = null
    private var connected = false
    private fun ensureOpen() { if (closed) throw IOException("Stream closed") }
    private fun remaining(deadline: Long): Int {
        ensureOpen(); val time = deadline - monotonicMillis()
        if (time <= 0) throw SocketTimeoutException("Connection timed out")
        return time.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    }
    private fun resolve(host: String, deadline: Long): Array<InetAddress> {
        if (':' in host || host.all { it in '0'..'9' || it == '.' }) return arrayOf(InetAddress.getByName(host))
        val pending = resolver.submit<Array<InetAddress>> { InetAddress.getAllByName(host) }
        try {
            while (true) {
                try { return pending.get(remaining(deadline).coerceAtMost(100).toLong(), TimeUnit.MILLISECONDS) }
                catch (_: TimeoutException) { }
            }
        } finally { pending.cancel(false); resolver.purge() }
    }
    private fun factory(insecure: Boolean, deadline: Long): SSLSocketFactory {
        val pending = if (insecure) insecureTestFactory else verifiedFactory
        while (true) {
            try { return pending.get(remaining(deadline).coerceAtMost(100).toLong(),TimeUnit.MILLISECONDS) }
            catch (_: TimeoutException) { }
        }
    }
    actual fun connect(host: String, port: Int, tls: Boolean, serverName: String, certificateName: String, timeoutMillis: Int, insecureForTests: Boolean) {
        require(port in 1..65535 && timeoutMillis > 0); connectLock.lock()
        try {
            synchronized(state) { ensureOpen(); check(!connected && socket == null) { "Already connected" } }
            val deadline = monotonicMillis() + timeoutMillis
            val tlsFactory = if (tls) factory(insecureForTests,deadline) else null
            var raw: Socket? = null; var lastError: Exception? = null
            val addresses = resolve(host, deadline)
            for (address in addresses) {
                val attempt = Socket(); synchronized(state) { ensureOpen(); socket = attempt }
                try {
                    attempt.tcpNoDelay = true
                    attempt.connect(InetSocketAddress(address, port), remaining(deadline).let { if (addresses.size > 1) it.coerceAtMost(3000) else it })
                    raw = attempt; break
                } catch (error: Exception) {
                    attempt.close(); lastError = error; synchronized(state) { if (socket === attempt) socket = null }; ensureOpen()
                }
            }
            var established = raw ?: throw (lastError ?: IOException("No address for $host"))
            if (tls) {
                val ssl = checkNotNull(tlsFactory).createSocket(established,certificateName,port,true) as SSLSocket
                synchronized(state) { if (closed) { ssl.close(); throw IOException("Stream closed") }; socket = ssl }
                val parameters = ssl.sslParameters
                parameters.endpointIdentificationAlgorithm = if (insecureForTests || certificateName != serverName) null else "HTTPS"
                parameters.serverNames = if (':' in serverName || serverName.all { it in '0'..'9' || it == '.' }) emptyList() else listOf(SNIHostName(serverName))
                ssl.sslParameters = parameters
                ssl.enabledProtocols = ssl.supportedProtocols.filter { it == "TLSv1.2" || it == "TLSv1.3" }.toTypedArray()
                ssl.soTimeout = remaining(deadline); ssl.startHandshake()
                if (!insecureForTests && certificateName != serverName) verifyOverrideName(ssl, certificateName)
                ssl.soTimeout = 0; established = ssl
            }
            synchronized(state) { ensureOpen(); socket = established; connected = true }
        } catch (error: Throwable) { close(); throw error } finally { connectLock.unlock() }
    }
    private fun current(): Socket = synchronized(state) { ensureOpen(); check(connected) { "Not connected" }; socket ?: throw IOException("Stream closed") }
    private fun bounds(buffer: ByteArray, offset: Int, length: Int) { require(length >= 0 && offset >= 0 && length <= buffer.size && offset <= buffer.size - length) }
    actual fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        bounds(buffer, offset, length); if (length == 0) return 0; readLock.lock()
        try { return current().getInputStream().read(buffer, offset, length) } finally { readLock.unlock() }
    }
    actual fun write(buffer: ByteArray, offset: Int, length: Int) {
        bounds(buffer, offset, length); writeLock.lock()
        try { current().getOutputStream().write(buffer, offset, length) } finally { writeLock.unlock() }
    }
    actual fun close() {
        val old = synchronized(state) { closed = true; connected = false; socket.also { socket = null } }
        try { old?.close() } catch (_: IOException) { }
    }
}
