package io.tailcat.wireguard

import io.tailcat.crypto.TailcatCrypto as Crypto
import io.tailcat.platform.wallClockMillis

/** One peer's Noise_IKpsk2 session. The owner serializes access and drives timers. */
internal class WireGuard(privateKey: ByteArray,peerPublicKey: ByteArray,presharedKey: ByteArray=ByteArray(32)) {
    enum class Failure { INVALID_KEY,INVALID_PACKET,INVALID_MAC,UNEXPECTED_MESSAGE,WRONG_PEER,REPLAY,HANDSHAKE_RATE_LIMITED,NOT_ESTABLISHED,EXPIRED,INVALID_TIME }
    class WireGuardException(val failure: Failure) : Exception(failure.name)
    data class ReceiveResult(val response: ByteArray?=null,val plaintext: ByteArray?=null,val handshakeCompleted: Boolean=false)
    private val privateKey=privateKey.copyOf(); private val peerPublicKey=peerPublicKey.copyOf(); private val presharedKey=presharedKey.copyOf()
    private val publicKey: ByteArray; private val staticShared: ByteArray
    init {
        if (privateKey.size!=32 || peerPublicKey.size!=32 || presharedKey.size!=32) fail(Failure.INVALID_KEY)
        publicKey=Crypto.publicKey(privateKey); staticShared=Crypto.sharedSecret(privateKey,peerPublicKey)
    }
    private data class Initiation(val chain: ByteArray,val hash: ByteArray,val ephemeral: ByteArray,val localIndex: UInt,val created: Long)
    private data class Outbound(val packet: ByteArray,val localIndex: UInt,val created: Long)
    private data class Session(val sendKey: ByteArray,val receiveKey: ByteArray,val localIndex: UInt,val remoteIndex: UInt,val created: Long,val initiator: Boolean,var sendCounter: ULong=0UL,var replay: ReplayWindow=ReplayWindow())
    private var pending: Initiation?=null; private var previous: Session?=null; private var current: Session?=null; private var next: Session?=null
    private var lastTimestamp: ByteArray?=null; private var lastSentTimestamp: ByteArray?=null; private var lastInitiationReceived: Long?=null
    private var lastOutbound: Outbound?=null; private var cookie: ByteArray?=null; private var cookieReceivedAt: Long?=null
    private var cookieSecret: ByteArray?=null; private var cookieSecretAt: Long?=null
    val isEstablished: Boolean get()=current!=null
    val remoteIndex: UInt? get()=current?.remoteIndex
    val receiveIndices: Set<UInt> get()=listOfNotNull(pending?.localIndex,previous?.localIndex,current?.localIndex,next?.localIndex).toSet()
    fun needsRekey(nowMillis: Long): Boolean {
        val session=current ?: return true
        return session.sendCounter >= (1UL shl 60) || nowMillis-session.created >= if (session.initiator) 120_000 else 165_000
    }
    fun maintenance(nowMillis: Long) {
        if (previous?.let { !alive(nowMillis,it.created,180_000) }==true) previous=null
        if (current?.let { !alive(nowMillis,it.created,180_000) }==true) current=null
        if (next?.let { !alive(nowMillis,it.created,180_000) }==true) next=null
        if (pending?.let { !alive(nowMillis,it.created,180_000) }==true) pending=null
        if (lastOutbound?.let { !alive(nowMillis,it.created,120_000) }==true) lastOutbound=null
        if (cookieReceivedAt?.let { !alive(nowMillis,it,115_000) }==true) { cookie=null; cookieReceivedAt=null }
        if (cookieSecretAt?.let { !alive(nowMillis,it,120_000) }==true) { cookieSecret=null; cookieSecretAt=null }
    }
    fun initiate(nowMillis: Long,wallMillis: Long=wallClockMillis()): ByteArray = initiateHandshake(nowMillis,wallMillis)
    fun initiateHandshake(nowMillis: Long,wallMillis: Long=wallClockMillis()): ByteArray {
        val ephemeral=Crypto.randomBytes(32); val ephemeralPublic=Crypto.publicKey(ephemeral); val index=freshIndex()
        var chain=initialChain; var hash=hash(initialHash,peerPublicKey)
        chain=kdf(chain,ephemeralPublic,1)[0]; hash=hash(hash,ephemeralPublic)
        var keys=kdf(chain,Crypto.sharedSecret(ephemeral,peerPublicKey),2); chain=keys[0]
        val encryptedStatic=Crypto.seal(publicKey,keys[1],zeroNonce,hash); hash=hash(hash,encryptedStatic)
        keys=kdf(chain,staticShared,2); chain=keys[0]; var timestamp=timestamp(wallMillis)
        val old=lastSentTimestamp
        if (old!=null && !before(old,timestamp)) {
            timestamp=old.copyOf(); for (i in timestamp.lastIndex downTo 0) { timestamp[i]=(u(timestamp[i])+1).toByte(); if (timestamp[i]!=0.toByte()) break }
        }
        val encryptedTimestamp=Crypto.seal(timestamp,keys[1],zeroNonce,hash); hash=hash(hash,encryptedTimestamp)
        val packet=addMACs(le(1U)+le(index)+ephemeralPublic+encryptedStatic+encryptedTimestamp,nowMillis)
        lastSentTimestamp=timestamp; pending=Initiation(chain,hash,ephemeral,index,nowMillis); lastOutbound=Outbound(packet.copyOf(),index,nowMillis)
        return packet
    }
    fun receive(datagram: ByteArray,nowMillis: Long,source: ByteArray?=null,requireCookie: Boolean=false): ReceiveResult {
        val type=packetType(datagram) ?: fail(Failure.INVALID_PACKET)
        if (type==1 || type==2) {
            if (datagram.size!=(if (type==1) 148 else 92)) fail(Failure.INVALID_PACKET)
            val offset=datagram.size-32; val key=Crypto.blake2s("mac1----".encodeToByteArray()+publicKey)
            if (!Crypto.constantTimeEqual(mac(datagram.copyOf(offset),key),datagram.copyOfRange(offset,offset+16))) fail(Failure.INVALID_MAC)
            if (requireCookie) {
                if (source==null) fail(Failure.INVALID_PACKET)
                val reply=checkCookie(datagram,source,nowMillis); if (reply!=null) return ReceiveResult(response=reply)
            }
        }
        return when(type) { 1 -> consumeInitiation(datagram,nowMillis); 2 -> consumeResponse(datagram,nowMillis); 3 -> consumeCookie(datagram,nowMillis); 4 -> consumeTransport(datagram,nowMillis); else -> fail(Failure.INVALID_PACKET) }
    }
    fun encrypt(plaintext: ByteArray,nowMillis: Long): ByteArray {
        val session=current ?: fail(Failure.NOT_ESTABLISHED)
        if (!alive(nowMillis,session.created,180_000) || session.sendCounter>=rejectAfterMessages) fail(Failure.EXPIRED)
        if (plaintext.size>65535) fail(Failure.INVALID_PACKET)
        val counter=session.sendCounter; val encrypted=Crypto.seal(plaintext.copyOf(plaintext.size+(16-plaintext.size%16)%16),session.sendKey,nonce(counter))
        session.sendCounter++; return le(4U)+le(session.remoteIndex)+le(counter)+encrypted
    }
    private fun consumeInitiation(packet: ByteArray,now: Long): ReceiveResult {
        val remoteIndex=u32(packet,4); val remoteEphemeral=packet.copyOfRange(8,40)
        var hash=hash(initialHash,publicKey); hash=hash(hash,remoteEphemeral); var chain=kdf(initialChain,remoteEphemeral,1)[0]
        var keys=kdf(chain,Crypto.sharedSecret(privateKey,remoteEphemeral),2); chain=keys[0]
        val remoteStatic=Crypto.open(packet.copyOfRange(40,88),keys[1],zeroNonce,hash)
        if (!Crypto.constantTimeEqual(remoteStatic,peerPublicKey)) fail(Failure.WRONG_PEER)
        hash=hash(hash,packet.copyOfRange(40,88)); keys=kdf(chain,staticShared,2); chain=keys[0]
        val timestamp=Crypto.open(packet.copyOfRange(88,116),keys[1],zeroNonce,hash); hash=hash(hash,packet.copyOfRange(88,116))
        val old=lastTimestamp; if (old!=null && !before(old,timestamp)) fail(Failure.REPLAY)
        val received=lastInitiationReceived; if (received!=null && now-received<20) fail(Failure.HANDSHAKE_RATE_LIMITED)
        val localIndex=freshIndex(); val ephemeral=Crypto.randomBytes(32); val ephemeralPublic=Crypto.publicKey(ephemeral)
        hash=hash(hash,ephemeralPublic); chain=kdf(chain,ephemeralPublic,1)[0]; chain=kdf(chain,Crypto.sharedSecret(ephemeral,remoteEphemeral),1)[0]
        chain=kdf(chain,Crypto.sharedSecret(ephemeral,peerPublicKey),1)[0]; keys=kdf(chain,presharedKey,3); chain=keys[0]; hash=hash(hash,keys[1])
        val encryptedEmpty=Crypto.seal(byteArrayOf(),keys[2],zeroNonce,hash); val transportKeys=kdf(chain,byteArrayOf(),2)
        val response=addMACs(le(2U)+le(localIndex)+le(remoteIndex)+ephemeralPublic+encryptedEmpty,now)
        next=Session(transportKeys[1],transportKeys[0],localIndex,remoteIndex,now,false); lastTimestamp=timestamp; lastInitiationReceived=now
        lastOutbound=Outbound(response.copyOf(),localIndex,now); return ReceiveResult(response=response)
    }
    private fun consumeResponse(packet: ByteArray,now: Long): ReceiveResult {
        val initiation=pending ?: fail(Failure.UNEXPECTED_MESSAGE)
        if (u32(packet,8)!=initiation.localIndex) fail(Failure.UNEXPECTED_MESSAGE)
        if (!alive(now,initiation.created,180_000)) fail(Failure.EXPIRED)
        val ephemeral=packet.copyOfRange(12,44); var hash=hash(initiation.hash,ephemeral); var chain=kdf(initiation.chain,ephemeral,1)[0]
        chain=kdf(chain,Crypto.sharedSecret(initiation.ephemeral,ephemeral),1)[0]; chain=kdf(chain,Crypto.sharedSecret(privateKey,ephemeral),1)[0]
        val keys=kdf(chain,presharedKey,3); hash=hash(hash,keys[1]); Crypto.open(packet.copyOfRange(44,60),keys[2],zeroNonce,hash)
        val transportKeys=kdf(keys[0],byteArrayOf(),2); previous=current
        current=Session(transportKeys[0],transportKeys[1],initiation.localIndex,u32(packet,4),now,true); pending=null
        return ReceiveResult(response=encrypt(byteArrayOf(),now),handshakeCompleted=true)
    }
    private fun consumeTransport(packet: ByteArray,now: Long): ReceiveResult {
        if (packet.size !in 32..65568) fail(Failure.INVALID_PACKET)
        val index=u32(packet,4); val counter=u64(packet,8); val slot: Int; val session: Session
        when { next?.localIndex==index -> { session=next!!; slot=2 }; current?.localIndex==index -> { session=current!!; slot=1 }; previous?.localIndex==index -> { session=previous!!; slot=0 }; else -> fail(Failure.UNEXPECTED_MESSAGE) }
        if (!alive(now,session.created,180_000)) fail(Failure.EXPIRED)
        val replay=session.replay.copy(); if (!replay.accept(counter)) fail(Failure.REPLAY)
        val padded=Crypto.open(packet.copyOfRange(16,packet.size),session.receiveKey,nonce(counter)); session.replay=replay
        when(slot) { 2 -> { previous=current; current=session; next=null }; 1 -> current=session; else -> previous=session }
        return ReceiveResult(plaintext=unpadIP(padded),handshakeCompleted=slot==2)
    }
    private fun consumeCookie(packet: ByteArray,now: Long): ReceiveResult {
        if (packet.size!=64) fail(Failure.INVALID_PACKET)
        val outbound=lastOutbound ?: fail(Failure.UNEXPECTED_MESSAGE)
        if (u32(packet,4)!=outbound.localIndex || !alive(now,outbound.created,120_000)) fail(Failure.UNEXPECTED_MESSAGE)
        val key=Crypto.blake2s("cookie--".encodeToByteArray()+peerPublicKey); val mac1=outbound.packet.copyOfRange(outbound.packet.size-32,outbound.packet.size-16)
        val value=Crypto.xOpen(packet.copyOfRange(32,64),key,packet.copyOfRange(8,32),mac1); if (value.size!=16) fail(Failure.INVALID_PACKET)
        cookie=value; cookieReceivedAt=now; val response=addMACs(outbound.packet.copyOf(outbound.packet.size-32),now)
        lastOutbound=Outbound(response.copyOf(),outbound.localIndex,outbound.created); return ReceiveResult(response=response)
    }
    private fun checkCookie(packet: ByteArray,source: ByteArray,now: Long): ByteArray? {
        if (cookieSecret==null || !alive(now,cookieSecretAt!!,120_000)) { cookieSecret=Crypto.randomBytes(32); cookieSecretAt=now }
        val expectedCookie=mac(source,cookieSecret!!)
        if (Crypto.constantTimeEqual(mac(packet.copyOf(packet.size-16),expectedCookie),packet.copyOfRange(packet.size-16,packet.size))) return null
        val key=Crypto.blake2s("cookie--".encodeToByteArray()+publicKey); val nonce=Crypto.randomBytes(24); val mac1=packet.copyOfRange(packet.size-32,packet.size-16)
        return le(3U)+le(u32(packet,4))+nonce+Crypto.xSeal(expectedCookie,key,nonce,mac1)
    }
    private fun addMACs(body: ByteArray,now: Long): ByteArray {
        val key=Crypto.blake2s("mac1----".encodeToByteArray()+peerPublicKey); val packet=body+mac(body,key); val c=cookie; val received=cookieReceivedAt
        return packet+(if (c!=null && received!=null && alive(now,received,115_000)) mac(packet,c) else ByteArray(16))
    }
    private fun freshIndex(): UInt {
        val indices=receiveIndices; while (true) { val index=u32(Crypto.randomBytes(4),0); if (index!=0U && index !in indices) return index }
    }
    internal class ReplayWindow {
        private var highest: ULong?=null; private var bits=LongArray(129)
        fun copy(): ReplayWindow = ReplayWindow().also { it.highest=highest; it.bits=bits.copyOf() }
        fun accept(counter: ULong): Boolean {
            if (counter>=rejectAfterMessages) return false
            val high=highest
            if (high!=null) {
                if (counter<=high && high-counter>=8192UL) return false
                if (counter>high) {
                    val start=high/64UL+1UL; val end=counter/64UL
                    if (end>=start) { if (end-start>=128UL) bits.fill(0) else { var word=start; while (word<=end) { bits[(word%129UL).toInt()]=0; word++ } } }
                    highest=counter
                }
            } else highest=counter
            val index=((counter/64UL)%129UL).toInt(); val mask=1L shl (counter%64UL).toInt()
            if (bits[index] and mask !=0L) return false; bits[index]=bits[index] or mask; return true
        }
    }
    companion object {
        private val initialChain=Crypto.blake2s("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".encodeToByteArray())
        private val initialHash=Crypto.blake2s(initialChain+"WireGuard v1 zx2c4 Jason@zx2c4.com".encodeToByteArray())
        private val zeroNonce=ByteArray(12); private val rejectAfterMessages=ULong.MAX_VALUE-8192UL
        private fun fail(failure: Failure): Nothing = throw WireGuardException(failure)
        private fun alive(now: Long,created: Long,lifetime: Long): Boolean = now>=created && now-created<lifetime
        private fun hash(a: ByteArray,b: ByteArray)=Crypto.blake2s(a+b)
        private fun mac(data: ByteArray,key: ByteArray)=Crypto.blake2s(data,key,16)
        private fun kdf(key: ByteArray,input: ByteArray,count: Int): List<ByteArray> {
            val secret=Crypto.hmacBlake2s(key,input); var previous=byteArrayOf()
            return (1..count).map { previous=Crypto.hmacBlake2s(secret,previous+byteArrayOf(it.toByte())); previous }
        }
        private fun u(x: Byte)=x.toInt() and 255
        private fun le(value: UInt)=ByteArray(4) { (value shr (it*8)).toByte() }
        private fun le(value: ULong)=ByteArray(8) { (value shr (it*8)).toByte() }
        private fun u32(data: ByteArray,offset: Int): UInt { var result=0U; for (i in 0..3) result=result or (u(data[offset+i]).toUInt() shl (i*8)); return result }
        private fun u64(data: ByteArray,offset: Int): ULong { var result=0UL; for (i in 0..7) result=result or (u(data[offset+i]).toULong() shl (i*8)); return result }
        private fun nonce(counter: ULong)=ByteArray(4)+le(counter)
        fun packetType(packet: ByteArray): Int? = if (packet.size>=4) u32(packet,0).let { if (it<=Int.MAX_VALUE.toUInt()) it.toInt() else null } else null
        private fun timestamp(wallMillis: Long): ByteArray {
            if (wallMillis<0) fail(Failure.INVALID_TIME)
            val seconds=wallMillis/1000+0x400000000000000aL; val nanos=((wallMillis%1000)*1_000_000).toInt()
            return ByteArray(12) { if (it<8) (seconds ushr ((7-it)*8)).toByte() else (nanos ushr ((11-it)*8)).toByte() }
        }
        private fun before(a: ByteArray,b: ByteArray): Boolean { for (i in a.indices) { val x=u(a[i]); val y=u(b[i]); if (x!=y) return x<y }; return false }
        private fun unpadIP(data: ByteArray): ByteArray? {
            if (data.isEmpty()) return null
            val length: Int
            when(u(data[0]) ushr 4) {
                4 -> { if (data.size<20) fail(Failure.INVALID_PACKET); val header=(u(data[0]) and 15)*4; length=(u(data[2]) shl 8) or u(data[3]); if (header<20 || length<header) fail(Failure.INVALID_PACKET) }
                6 -> { if (data.size<40) fail(Failure.INVALID_PACKET); length=40+((u(data[4]) shl 8) or u(data[5])) }
                else -> fail(Failure.INVALID_PACKET)
            }
            if (length>data.size) fail(Failure.INVALID_PACKET); return data.copyOf(length)
        }
    }
}
