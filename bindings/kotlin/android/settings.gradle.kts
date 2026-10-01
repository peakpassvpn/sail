// The AAR of sail for Kotlin: the sources of ../src/main/kotlin, and
// libsail_jni for each ABI from ../jni. The JVM project one level up runs
// the tests on a desktop JVM; this one only packages.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.library") version
            (providers.gradleProperty("sail.agp").orNull ?: error("pass -Psail.agp=<Android Gradle plugin version>"))
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "sail-android"
