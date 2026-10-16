plugins { id("com.android.application") version "8.10.1"; kotlin("android") version "2.2.21" }
repositories {
    providers.gradleProperty("tailcatRepository").orNull?.let { maven { url = uri(it) } }
    mavenLocal(); google(); mavenCentral()
}
dependencies { implementation("io.tailcat:tailcat-kotlin:0.1.0") }
kotlin { jvmToolchain(21); compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
android {
    namespace = "io.tailcat.example"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    defaultConfig { applicationId = "io.tailcat.example"; minSdk = 24; targetSdk = 36; versionCode = 1; versionName = "1.0" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
