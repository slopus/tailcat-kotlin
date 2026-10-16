package io.tailcat.example

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import io.tailcat.TailcatClient

class MainActivity : Activity() {
    private val connectionLock = Any()
    private var client: TailcatClient? = null
    private var destroyed = false
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32,32,32,32) }
        val address = EditText(this).apply { hint = "Tailcat address" }
        val port = EditText(this).apply { hint = "TCP port"; setText("8080"); inputType = 2 }
        val result = TextView(this)
        val connect = Button(this).apply { text = "Send hello" }
        connect.setOnClickListener {
            connect.isEnabled = false
            val destination = address.text.toString(); val destinationPort = port.text.toString().toIntOrNull() ?: 8080
            Thread {
                try {
                    val connected = TailcatClient.connect(destination)
                    synchronized(connectionLock) {
                        if (destroyed) { connected.close(); return@Thread }
                        client = connected
                    }
                    try {
                        val stream = connected.dialTCP(destinationPort)
                        stream.write("hello from Android".encodeToByteArray()); stream.shutdownOutput()
                        val reply = stream.read().decodeToString(); stream.close()
                        runOnUiThread { result.text = reply }
                    } finally { connected.close(); synchronized(connectionLock) { client = null } }
                } catch (error: Exception) { runOnUiThread { result.text = error.message ?: "Connection failed" } }
                finally { runOnUiThread { connect.isEnabled = true } }
            }.start()
        }
        listOf(address,port,connect,result).forEach { layout.addView(it) }; setContentView(layout)
    }
    override fun onDestroy() {
        val connected = synchronized(connectionLock) { destroyed = true; client.also { client = null } }
        connected?.close()
        super.onDestroy()
    }
}
