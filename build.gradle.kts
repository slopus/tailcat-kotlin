plugins {
    kotlin("multiplatform") version "2.2.21"
    id("com.android.library") version "8.10.1"
    `maven-publish`
}

group = "io.tailcat"
version = "0.1.0"

kotlin {
    jvmToolchain(21)
    jvm { compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
    androidTarget {
        publishLibraryVariants("release")
        compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
    linuxX64 {
        val opensslLibDir = providers.gradleProperty("tailcat.opensslLibDir").orElse("/usr/lib/x86_64-linux-gnu")
        binaries.all { linkerOpts("-L${opensslLibDir.get()}", "--allow-shlib-undefined") }
        binaries.executable("tailcat-check") { entryPoint = "io.tailcat.check.main" }
        compilations.getByName("main").cinterops.create("openssl") {
            defFile(project.file("src/nativeInterop/cinterop/openssl.def"))
        }
    }
    linuxArm64 {
        compilations.getByName("main").cinterops.create("openssl") {
            defFile(project.file("src/nativeInterop/cinterop/openssl.def"))
        }
    }
    applyDefaultHierarchyTemplate()
    sourceSets {
        commonTest.dependencies { implementation(kotlin("test")) }
        val jvmAndAndroidMain by creating { dependsOn(commonMain.get()) }
        jvmMain.get().dependsOn(jvmAndAndroidMain)
        androidMain.get().dependsOn(jvmAndAndroidMain)
        androidUnitTest.get().kotlin.srcDir("src/jvmTest/kotlin")
    }
}

android {
    namespace = "io.tailcat"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    defaultConfig { minSdk = 24; testInstrumentationRunner = "io.tailcat.TailcatInstrumentation" }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")
}

tasks.register<JavaExec>("runJvmCheck") {
    dependsOn("jvmMainClasses")
    mainClass.set("io.tailcat.check.MainKt")
    classpath = files(kotlin.targets.getByName("jvm").compilations.getByName("main").output.allOutputs) +
        configurations.getByName("jvmRuntimeClasspath")
    providers.gradleProperty("checkArgs").orNull?.let { args(it.split(' ')) }
}

// Fixture configuration changes must invalidate test results, even with unchanged code.
tasks.withType<org.gradle.api.tasks.testing.AbstractTestTask>().configureEach {
    listOf("TAILCAT_LOCAL_RELAY_PORT", "TAILCAT_PLATFORM_TLS_HOST", "TAILCAT_PLATFORM_TLS_PORT",
        "TAILCAT_PLATFORM_SELF_TLS_HOST", "TAILCAT_PLATFORM_SELF_TLS_PORT").forEach { name ->
        inputs.property(name, providers.environmentVariable(name).orElse(""))
    }
}
