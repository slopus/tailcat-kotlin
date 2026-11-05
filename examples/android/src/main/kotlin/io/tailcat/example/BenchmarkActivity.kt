package io.tailcat.example

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import android.widget.TextView
import io.tailcat.benchmark.TailcatBenchmark
import java.io.File

/** Explicit debug benchmark entry; does nothing unless launched with mode=server or mode=client. */
class BenchmarkActivity : Activity() {
    private var benchmark: TailcatBenchmark? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val view = TextView(this).apply { text = "Tailcat benchmark starting"; setPadding(24, 24, 24, 24) }
        setContentView(view)
        val mode = intent.getStringExtra("mode") ?: return
        require(mode == "server" || mode == "client")
        val runId = (intent.getStringExtra("runId") ?: "benchmark").replace(Regex("[^A-Za-z0-9_-]"), "_")
        val file = File(filesDir, "$runId.jsonl")
        val arguments = mutableListOf(mode)
        for (key in listOf("address", "source", "target", "runId", "region", "relayFirst", "trials", "trial", "bytes", "warm", "recovery", "secondIndependent")) {
            intent.getStringExtra(key)?.let { arguments.add("$key=$it") }
        }
        val runner = TailcatBenchmark { line ->
            file.appendText(line + "\n")
            Log.i("TailcatBenchmark", line)
            runOnUiThread { view.text = line }
        }
        benchmark = runner
        Thread({
            try { runner.run(arguments.toTypedArray()) }
            catch (failure: Throwable) { Log.e("TailcatBenchmark", "Benchmark ended", failure) }
            finally { runner.close() }
        }, "tailcat-benchmark").start()
    }
    override fun onDestroy() { benchmark?.close(); super.onDestroy() }
}