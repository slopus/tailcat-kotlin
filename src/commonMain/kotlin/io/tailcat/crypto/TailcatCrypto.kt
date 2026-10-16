package io.tailcat.crypto

import io.tailcat.platform.secureRandom

/** Portable common Kotlin cryptography; no provider or platform dependency. */
internal object TailcatCrypto {
    class CryptoException(message: String) : Exception(message)
    private fun fail(message: String): Nothing = throw CryptoException(message)
    private fun checkKey(key: ByteArray) { if (key.size != 32) fail("Invalid key length") }
    fun randomBytes(count: Int): ByteArray { require(count >= 0); return secureRandom(count).also { check(it.size == count) } }
    fun constantTimeEqual(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var difference = 0
        for (i in a.indices) difference = difference or (a[i].toInt() xor b[i].toInt())
        return difference == 0
    }
    fun publicKey(privateKey: ByteArray): ByteArray = x25519(privateKey, ByteArray(32).also { it[0] = 9 })
    fun sharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val result = x25519(privateKey, publicKey); var nonzero = 0
        for (byte in result) nonzero = nonzero or byte.toInt()
        if (nonzero == 0) fail("Invalid low-order public key")
        return result
    }
    private fun u(x: Byte): Int = x.toInt() and 255
    private fun load32(b: ByteArray, i: Int): Int = u(b[i]) or (u(b[i+1]) shl 8) or (u(b[i+2]) shl 16) or (u(b[i+3]) shl 24)
    private fun word64(b: ByteArray, i: Int): Long = load32(b,i).toLong() and 0xffffffffL
    private fun put32(b: ByteArray, i: Int, x: Int) { for (j in 0..3) b[i+j] = (x ushr (j*8)).toByte() }
    private fun words(words: IntArray): ByteArray = ByteArray(words.size*4).also { out -> for (i in words.indices) put32(out,i*4,words[i]) }
    private fun rotr(x: Int, n: Int): Int = (x ushr n) or (x shl (32-n))
    private fun rotl(x: Int, n: Int): Int = (x shl n) or (x ushr (32-n))
    private val shaConstants = longArrayOf(
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2).map { it.toInt() }.toIntArray()
    private val iv = longArrayOf(0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19).map { it.toInt() }.toIntArray()
    fun sha256(data: ByteArray): ByteArray {
        require(data.size <= Int.MAX_VALUE-72)
        val bytes = data.copyOf(((data.size.toLong()+9+63)/64*64).toInt()); bytes[data.size] = 0x80.toByte()
        val bits = data.size.toLong()*8
        for (i in 0..7) bytes[bytes.size-1-i] = (bits ushr (i*8)).toByte()
        val state = iv.copyOf(); val w = IntArray(64)
        for (offset in bytes.indices step 64) {
            for (i in 0..15) { val j=offset+i*4; w[i]=(u(bytes[j]) shl 24) or (u(bytes[j+1]) shl 16) or (u(bytes[j+2]) shl 8) or u(bytes[j+3]) }
            for (i in 16..63) { val x=w[i-15]; val y=w[i-2]; w[i]=w[i-16]+(rotr(x,7) xor rotr(x,18) xor (x ushr 3))+w[i-7]+(rotr(y,17) xor rotr(y,19) xor (y ushr 10)) }
            var a=state[0]; var b=state[1]; var c=state[2]; var d=state[3]; var e=state[4]; var f=state[5]; var g=state[6]; var h=state[7]
            for (i in 0..63) {
                val t1=h+(rotr(e,6) xor rotr(e,11) xor rotr(e,25))+((e and f) xor (e.inv() and g))+shaConstants[i]+w[i]
                val t2=(rotr(a,2) xor rotr(a,13) xor rotr(a,22))+((a and b) xor (a and c) xor (b and c))
                h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2
            }
            val working=intArrayOf(a,b,c,d,e,f,g,h); for (i in 0..7) state[i]+=working[i]
        }
        return ByteArray(32).also { out -> for (i in 0..7) for (j in 0..3) out[i*4+j]=(state[i] ushr (24-j*8)).toByte() }
    }
    private fun hmac(key: ByteArray, message: ByteArray, hash: (ByteArray)->ByteArray): ByteArray {
        val k=(if (key.size>64) hash(key) else key).copyOf(64)
        val inner=ByteArray(64) { (k[it].toInt() xor 0x36).toByte() }; val outer=ByteArray(64) { (k[it].toInt() xor 0x5c).toByte() }
        return hash(outer+hash(inner+message))
    }
    fun hmacSHA256(key: ByteArray, message: ByteArray): ByteArray = hmac(key,message,::sha256)
    fun hmacBlake2s(key: ByteArray, message: ByteArray): ByteArray = hmac(key,message) { blake2s(it) }
    private val sigma = arrayOf(
        intArrayOf(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15),intArrayOf(14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3),
        intArrayOf(11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4),intArrayOf(7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8),
        intArrayOf(9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13),intArrayOf(2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9),
        intArrayOf(12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11),intArrayOf(13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10),
        intArrayOf(6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5),intArrayOf(10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0))
    fun blake2s(data: ByteArray, key: ByteArray = byteArrayOf(), digestLength: Int = 32): ByteArray {
        require(key.size<=32 && digestLength in 1..32); require(data.size<=Int.MAX_VALUE-127)
        val h=iv.copyOf(); h[0]=h[0] xor 0x01010000 xor (key.size shl 8) xor digestLength
        val input=if (key.isEmpty()) data else key.copyOf(64)+data; val blocks=maxOf(1,(input.size+63)/64)
        for (block in 0 until blocks) {
            val offset=block*64; val used=minOf(64,input.size-offset); val bytes=ByteArray(64)
            if (used>0) input.copyInto(bytes,0,offset,offset+used)
            val m=IntArray(16) { load32(bytes,it*4) }; val v=h+iv; val count=offset.toLong()+used
            v[12]=v[12] xor count.toInt(); v[13]=v[13] xor (count ushr 32).toInt(); if (block==blocks-1) v[14]=v[14].inv()
            fun g(a: Int,b: Int,c: Int,d: Int,x: Int,y: Int) {
                v[a]+=v[b]+x; v[d]=rotr(v[d] xor v[a],16); v[c]+=v[d]; v[b]=rotr(v[b] xor v[c],12)
                v[a]+=v[b]+y; v[d]=rotr(v[d] xor v[a],8); v[c]+=v[d]; v[b]=rotr(v[b] xor v[c],7)
            }
            for (s in sigma) {
                g(0,4,8,12,m[s[0]],m[s[1]]); g(1,5,9,13,m[s[2]],m[s[3]]); g(2,6,10,14,m[s[4]],m[s[5]]); g(3,7,11,15,m[s[6]],m[s[7]])
                g(0,5,10,15,m[s[8]],m[s[9]]); g(1,6,11,12,m[s[10]],m[s[11]]); g(2,7,8,13,m[s[12]],m[s[13]]); g(3,4,9,14,m[s[14]],m[s[15]])
            }
            for (i in 0..7) h[i]=h[i] xor v[i] xor v[i+8]
        }
        return words(h).copyOf(digestLength)
    }
    fun seal(plaintext: ByteArray,key: ByteArray,nonce: ByteArray,authenticating: ByteArray=byteArrayOf()): ByteArray {
        checkKey(key); if (nonce.size!=12) fail("Invalid nonce length")
        val ciphertext=chacha(plaintext,key,nonce,1)
        return ciphertext+poly1305(aeadInput(authenticating,ciphertext),chachaBlock(key,nonce,0).copyOf(32))
    }
    fun open(ciphertext: ByteArray,key: ByteArray,nonce: ByteArray,authenticating: ByteArray=byteArrayOf()): ByteArray {
        checkKey(key); if (nonce.size!=12) fail("Invalid nonce length"); if (ciphertext.size<16) fail("Authentication failed")
        val body=ciphertext.copyOf(ciphertext.size-16); val tag=poly1305(aeadInput(authenticating,body),chachaBlock(key,nonce,0).copyOf(32))
        if (!constantTimeEqual(tag,ciphertext.copyOfRange(ciphertext.size-16,ciphertext.size))) fail("Authentication failed")
        return chacha(body,key,nonce,1)
    }
    fun xSeal(plaintext: ByteArray,key: ByteArray,nonce: ByteArray,authenticating: ByteArray=byteArrayOf()): ByteArray {
        checkKey(key); if (nonce.size!=24) fail("Invalid nonce length")
        return seal(plaintext,hChaCha(key,nonce.copyOf(16)),ByteArray(4)+nonce.copyOfRange(16,24),authenticating)
    }
    fun xOpen(ciphertext: ByteArray,key: ByteArray,nonce: ByteArray,authenticating: ByteArray=byteArrayOf()): ByteArray {
        checkKey(key); if (nonce.size!=24) fail("Invalid nonce length")
        return open(ciphertext,hChaCha(key,nonce.copyOf(16)),ByteArray(4)+nonce.copyOfRange(16,24),authenticating)
    }
    private val chachaConstants=intArrayOf(0x61707865,0x3320646e,0x79622d32,0x6b206574)
    private fun chachaRounds(state: IntArray) {
        fun q(a: Int,b: Int,c: Int,d: Int) {
            state[a]+=state[b]; state[d]=rotl(state[d] xor state[a],16); state[c]+=state[d]; state[b]=rotl(state[b] xor state[c],12)
            state[a]+=state[b]; state[d]=rotl(state[d] xor state[a],8); state[c]+=state[d]; state[b]=rotl(state[b] xor state[c],7)
        }
        repeat(10) { q(0,4,8,12); q(1,5,9,13); q(2,6,10,14); q(3,7,11,15); q(0,5,10,15); q(1,6,11,12); q(2,7,8,13); q(3,4,9,14) }
    }
    private fun hChaCha(key: ByteArray,nonce: ByteArray): ByteArray {
        val state=chachaConstants+IntArray(8) { load32(key,it*4) }+IntArray(4) { load32(nonce,it*4) }; chachaRounds(state)
        return words(intArrayOf(0,1,2,3,12,13,14,15).map { state[it] }.toIntArray())
    }
    private fun chachaBlock(key: ByteArray,nonce: ByteArray,counter: Int): ByteArray {
        val state=chachaConstants+IntArray(8) { load32(key,it*4) }+intArrayOf(counter)+IntArray(3) { load32(nonce,it*4) }
        val working=state.copyOf(); chachaRounds(working); return words(IntArray(16) { working[it]+state[it] })
    }
    private fun chacha(data: ByteArray,key: ByteArray,nonce: ByteArray,counter: Int): ByteArray {
        val output=ByteArray(data.size)
        for (offset in data.indices step 64) { val block=chachaBlock(key,nonce,counter+offset/64); for (j in 0 until minOf(64,data.size-offset)) output[offset+j]=(data[offset+j].toInt() xor block[j].toInt()).toByte() }
        return output
    }
    private fun aeadInput(aad: ByteArray,ciphertext: ByteArray): ByteArray {
        val first=aad.size.toLong()+((16-aad.size%16)%16); val second=ciphertext.size.toLong()+((16-ciphertext.size%16)%16)
        require(first+second+16<=Int.MAX_VALUE); val output=ByteArray((first+second+16).toInt()); aad.copyInto(output); ciphertext.copyInto(output,first.toInt())
        for (i in 0..7) { output[output.size-16+i]=(aad.size.toLong() ushr (i*8)).toByte(); output[output.size-8+i]=(ciphertext.size.toLong() ushr (i*8)).toByte() }
        return output
    }
    internal fun poly1305(message: ByteArray,key: ByteArray): ByteArray {
        checkKey(key); val mask=0x3ffffffL
        val r=longArrayOf(word64(key,0) and mask,(word64(key,3) ushr 2) and 0x3ffff03,(word64(key,6) ushr 4) and 0x3ffc0ff,(word64(key,9) ushr 6) and 0x3f03fff,(word64(key,12) ushr 8) and 0x00fffff)
        val h=LongArray(5)
        for (offset in message.indices step 16) {
            val length=minOf(16,message.size-offset); val block=ByteArray(17); message.copyInto(block,0,offset,offset+length); block[length]=1
            h[0]+=word64(block,0) and mask; h[1]+=(word64(block,3) ushr 2) and mask; h[2]+=(word64(block,6) ushr 4) and mask; h[3]+=(word64(block,9) ushr 6) and mask
            h[4]+=(word64(block,12) ushr 8) or (u(block[16]).toLong() shl 24)
            val d=LongArray(5)
            for (i in 0..4) for (j in 0..4) d[i]+=h[j]*r[(i-j+5)%5]*(if (j>i) 5 else 1)
            for (i in 0..3) { d[i+1]+=d[i] ushr 26; h[i]=d[i] and mask }
            h[4]=d[4] and mask; h[0]+=(d[4] ushr 26)*5; h[1]+=h[0] ushr 26; h[0]=h[0] and mask
        }
        for (i in 1..3) { h[i+1]+=h[i] ushr 26; h[i]=h[i] and mask }
        h[0]+=(h[4] ushr 26)*5; h[4]=h[4] and mask; h[1]+=h[0] ushr 26; h[0]=h[0] and mask
        val g=h.copyOf(); g[0]+=5
        for (i in 0..3) { g[i+1]+=g[i] ushr 26; g[i]=g[i] and mask }
        val select=-(g[4] ushr 26); g[4]=g[4] and mask
        for (i in 0..4) h[i]=(h[i] and select.inv()) or (g[i] and select)
        val out=longArrayOf((h[0] or (h[1] shl 26)) and 0xffffffffL,((h[1] ushr 6) or (h[2] shl 20)) and 0xffffffffL,((h[2] ushr 12) or (h[3] shl 14)) and 0xffffffffL,((h[3] ushr 18) or (h[4] shl 8)) and 0xffffffffL)
        var carry=0L
        for (i in 0..3) { out[i]+=word64(key,16+i*4)+carry; carry=out[i] ushr 32 }
        return words(out.map { it.toInt() }.toIntArray())
    }
    private fun x25519(privateKey: ByteArray,publicKey: ByteArray): ByteArray {
        checkKey(privateKey); checkKey(publicKey); val scalar=privateKey.copyOf(); val point=publicKey.copyOf()
        scalar[0]=(u(scalar[0]) and 248).toByte(); scalar[31]=((u(scalar[31]) and 127) or 64).toByte(); point[31]=(u(point[31]) and 127).toByte()
        fun carry(v: LongArray) {
            for (i in 0..15) { v[i]+=1L shl 16; val c=v[i] shr 16; v[i]-=c shl 16; if (i<15) v[i+1]+=c-1 else v[0]+=38*(c-1) }
        }
        fun swap(a: LongArray,b: LongArray,bit: Long) { val mask=-bit; for (i in 0..15) { val t=mask and (a[i] xor b[i]); a[i]=a[i] xor t; b[i]=b[i] xor t } }
        fun add(a: LongArray,b: LongArray)=LongArray(16) { a[it]+b[it] }
        fun sub(a: LongArray,b: LongArray)=LongArray(16) { a[it]-b[it] }
        fun mul(a: LongArray,b: LongArray): LongArray {
            val t=LongArray(31); for (i in 0..15) for (j in 0..15) t[i+j]+=a[i]*b[j]
            for (i in 0..14) t[i]+=38*t[i+16]
            val r=t.copyOf(16); carry(r); carry(r); return r
        }
        fun square(a: LongArray)=mul(a,a)
        val x=LongArray(16) { u(point[2*it]).toLong()+(u(point[2*it+1]).toLong() shl 8) }
        var a=LongArray(16).also { it[0]=1 }; var b=x.copyOf(); var c=LongArray(16); var d=LongArray(16).also { it[0]=1 }
        val constant=LongArray(16).also { it[0]=0xdb41; it[1]=1 }
        for (i in 254 downTo 0) {
            val bit=((u(scalar[i/8]) ushr (i%8)) and 1).toLong(); swap(a,b,bit); swap(c,d,bit)
            val e=add(a,c); a=sub(a,c); c=add(b,d); b=sub(b,d); d=square(e); val f=square(a); a=mul(c,a); c=mul(b,e)
            val e2=add(a,c); a=sub(a,c); b=square(a); c=sub(d,f); a=mul(c,constant); a=add(a,d); c=mul(c,a); a=mul(d,f); d=mul(b,x); b=square(e2)
            swap(a,b,bit); swap(c,d,bit)
        }
        var inverse=c.copyOf(); for (i in 253 downTo 0) { inverse=square(inverse); if (i!=2 && i!=4) inverse=mul(inverse,c) }
        val result=mul(a,inverse); repeat(3) { carry(result) }
        repeat(2) {
            val m=result.copyOf(); m[0]-=0xffed
            for (i in 1..14) { m[i]-=0xffff+((m[i-1] shr 16) and 1); m[i-1]=m[i-1] and 0xffff }
            m[15]-=0x7fff+((m[14] shr 16) and 1); val bit=(m[15] shr 16) and 1; m[14]=m[14] and 0xffff; swap(result,m,1-bit)
        }
        return ByteArray(32) { (result[it/2] shr ((it%2)*8)).toByte() }
    }
    private fun salsaState(key: ByteArray,nonce: ByteArray): IntArray = intArrayOf(chachaConstants[0],load32(key,0),load32(key,4),load32(key,8),load32(key,12),chachaConstants[1],load32(nonce,0),load32(nonce,4),load32(nonce,8),load32(nonce,12),chachaConstants[2],load32(key,16),load32(key,20),load32(key,24),load32(key,28),chachaConstants[3])
    private fun salsaRounds(input: IntArray): IntArray {
        val x=input.copyOf()
        fun q(a: Int,b: Int,c: Int,d: Int) { x[b]=x[b] xor rotl(x[a]+x[d],7); x[c]=x[c] xor rotl(x[b]+x[a],9); x[d]=x[d] xor rotl(x[c]+x[b],13); x[a]=x[a] xor rotl(x[d]+x[c],18) }
        repeat(10) { q(0,4,8,12); q(5,9,13,1); q(10,14,2,6); q(15,3,7,11); q(0,1,2,3); q(5,6,7,4); q(10,11,8,9); q(15,12,13,14) }
        return x
    }
    internal fun hsalsa(key: ByteArray,nonce: ByteArray): ByteArray {
        checkKey(key); require(nonce.size==16); val x=salsaRounds(salsaState(key,nonce)); return words(intArrayOf(0,5,10,15,6,7,8,9).map { x[it] }.toIntArray())
    }
    internal fun salsaStream(key: ByteArray,nonce: ByteArray,count: Int): ByteArray {
        checkKey(key); if (nonce.size!=24) fail("Invalid nonce length"); require(count>=0)
        val subkey=hsalsa(key,nonce.copyOf(16)); val state=salsaState(subkey,nonce.copyOfRange(16,24)+ByteArray(8)); val output=ByteArray(count)
        for (offset in output.indices step 64) { val x=salsaRounds(state); val block=words(IntArray(16) { x[it]+state[it] }); block.copyInto(output,offset,0,minOf(64,count-offset)); state[8]++; if (state[8]==0) state[9]++ }
        return output
    }
}

internal object NaClBox {
    fun publicKey(privateKey: ByteArray): ByteArray = TailcatCrypto.publicKey(privateKey)
    private fun key(publicKey: ByteArray,privateKey: ByteArray): ByteArray = TailcatCrypto.hsalsa(TailcatCrypto.sharedSecret(privateKey,publicKey),ByteArray(16))
    fun seal(message: ByteArray,nonce: ByteArray,publicKey: ByteArray,privateKey: ByteArray): ByteArray {
        require(message.size<=Int.MAX_VALUE-32); val stream=TailcatCrypto.salsaStream(key(publicKey,privateKey),nonce,message.size+32)
        val ciphertext=ByteArray(message.size) { (message[it].toInt() xor stream[it+32].toInt()).toByte() }
        return TailcatCrypto.poly1305(ciphertext,stream.copyOf(32))+ciphertext
    }
    fun open(message: ByteArray,nonce: ByteArray,publicKey: ByteArray,privateKey: ByteArray): ByteArray {
        if (message.size<16) throw TailcatCrypto.CryptoException("Authentication failed"); require(message.size<=Int.MAX_VALUE-16)
        val stream=TailcatCrypto.salsaStream(key(publicKey,privateKey),nonce,message.size+16); val ciphertext=message.copyOfRange(16,message.size)
        val tag=TailcatCrypto.poly1305(ciphertext,stream.copyOf(32))
        if (!TailcatCrypto.constantTimeEqual(tag,message.copyOf(16))) throw TailcatCrypto.CryptoException("Authentication failed")
        return ByteArray(ciphertext.size) { (ciphertext[it].toInt() xor stream[it+32].toInt()).toByte() }
    }
}
