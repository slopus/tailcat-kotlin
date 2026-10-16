plugins { kotlin("multiplatform") version "2.2.21" }
repositories {
    providers.gradleProperty("tailcatRepository").orNull?.let { maven { url = uri(it) } }
    mavenLocal(); mavenCentral()
}
kotlin {
    linuxX64 {
        binaries.executable {
            entryPoint = "example.main"
            linkerOpts("-L${providers.gradleProperty("tailcat.opensslLibDir").orElse("/usr/lib/x86_64-linux-gnu").get()}", "--allow-shlib-undefined")
        }
    }
    sourceSets.commonMain.dependencies { implementation("io.tailcat:tailcat-kotlin:0.1.0") }
}
