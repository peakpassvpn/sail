// sail's AAR: io.github.peakpassvpn.sail, minSdk 24 (matching rules by app
// needs API 29: the host checks). The release pipeline builds sail-ffi's
// static library for each ABI first and passes where they are:
//
//   gradle -p bindings/kotlin/android assembleRelease \
//     -Psail.libDir=<dir with <ABI>/libsail.a> -Psail.includeDir=<sail-ffi/include>
//
// The Android Gradle plugin's version is the pipeline's to pin
// (-Psail.agp=…), with the NDK and SDK it installs.

plugins {
    id("com.android.library")
    kotlin("plugin.serialization") version "2.4.10"
}

fun required(name: String): String =
    providers.gradleProperty(name).orNull ?: error("pass -P$name=…")

android {
    namespace = "io.github.peakpassvpn.sail"
    compileSdk = 36
    // The NDK the static libraries were built with, so that their C++
    // and the runtime linked to them are of one version.
    providers.gradleProperty("sail.ndkPath").orNull?.let { ndkPath = it }
    providers.gradleProperty("sail.ndkVersion").orNull?.let { ndkVersion = it }

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DANDROID_STL=c++_static",
                    "-DSAIL_LIB_DIR=${required("sail.libDir")}",
                    "-DSAIL_INCLUDE_DIR=${required("sail.includeDir")}",
                )
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("../jni/CMakeLists.txt")
        }
    }

    sourceSets {
        getByName("main") {
            kotlin.srcDir("../src/main/kotlin")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
}
