plugins { kotlin("jvm") version "2.2.21"; application }
repositories {
    providers.gradleProperty("tailcatRepository").orNull?.let { maven { url = uri(it) } }
    mavenLocal(); mavenCentral()
}
dependencies { implementation("io.tailcat:tailcat-kotlin:0.1.0") }
kotlin { jvmToolchain(21); compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
application { mainClass.set("example.MainKt") }
