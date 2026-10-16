package io.tailcat

/** Device smoke entry for environments where PackageManager is unavailable. */
object AndroidCheck {
    @JvmStatic fun main(args: Array<String>) {
        println("Android tailcat entry: API ${android.os.Build.VERSION.SDK_INT}")
        try { io.tailcat.check.main(args) }
        catch (failure: Throwable) {
            failure.printStackTrace(System.err)
            kotlin.system.exitProcess(1)
        }
    }
}
