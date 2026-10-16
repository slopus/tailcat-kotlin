package io.tailcat

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import io.tailcat.crypto.TailcatCrypto

/** No test runtime dependency: executes the real embedded library in Android. */
class TailcatInstrumentation : Instrumentation() {
    private var arguments = Bundle()
    override fun onCreate(arguments: Bundle?) { super.onCreate(arguments); this.arguments = arguments ?: Bundle(); start() }
    override fun onStart() {
        val output = Bundle()
        try {
            check(TailcatCrypto.sha256("abc".encodeToByteArray()).hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            arguments.getString("address")?.let { address ->
                val args = mutableListOf("client",address,arguments.getString("bytes") ?: "262144")
                if (arguments.getString("plain") == "true") args.add("plain")
                io.tailcat.check.main(args.toTypedArray())
            }
            output.putString("stream","PASS Android crypto and embedded TCP/UDP transfer\n")
            finish(Activity.RESULT_OK,output)
        } catch (error: Throwable) {
            output.putString("stream","FAIL ${error.stackTraceToString()}\n")
            finish(Activity.RESULT_CANCELED,output)
        }
    }
}
