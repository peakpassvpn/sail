// An app that runs sail in a VpnService, and its instrumented tests, on an
// emulator: CI's android-emulator job. It builds the AAR's module (../android)
// as a project of its own, for the ABIs -Psail.abis names, from the static
// libraries -Psail.libDir holds:
//
//   gradle -p bindings/kotlin/android-test connectedDebugAndroidTest \
//     -Psail.agp=9.4.1 -Psail.abis=x86_64 \
//     -Psail.libDir=<dir with x86_64/libsail.a> -Psail.includeDir=<sail-ffi/include>
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        val agp = providers.gradleProperty("sail.agp").orNull
            ?: error("pass -Psail.agp=<Android Gradle plugin version>")
        id("com.android.application") version agp
        id("com.android.library") version agp
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "sail-android-test"
include(":sail")
project(":sail").projectDir = file("../android")
