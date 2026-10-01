// sail for Kotlin: the C ABI (sail-ffi/include/sail.h) through
// jni/sail_jni.c. The sources are plain Kotlin, so a desktop JVM runs the
// tests (`gradle test`, after jni/build-host.sh); Android's AAR is built
// from the same sources by the release pipeline.

plugins {
    kotlin("jvm") version "2.4.10"
    kotlin("plugin.serialization") version "2.4.10"
}

group = "io.github.peakpassvpn"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
    // The JNI library jni/build-host.sh builds, with libsail in it.
    systemProperty("java.library.path", layout.buildDirectory.dir("jni").get().asFile.path)
    testLogging { events("passed", "failed"); showStandardStreams = false }
}
