// sail's AAR: io.github.peakpassvpn.sail, minSdk 24 (matching rules by app
// needs API 29: the host checks). The release pipeline builds sail-ffi's
// static library for each ABI first and passes where they are:
//
//   gradle -p bindings/kotlin/android assembleRelease \
//     -Psail.agp=9.4.1 \
//     -Psail.ndkPath=<NDK r27d> -Psail.ndkVersion=27.3.13750724 \
//     -Psail.libDir=<dir with <ABI>/libsail.a> -Psail.includeDir=<sail-ffi/include>
//
// The Android Gradle plugin's version is the pipeline's to pin, with the
// NDK and SDK it installs: scripts/release/package-aar.sh passes them all.
// The NDK is the one the static libraries were built with.

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
    // AGP checks the two agree, so they come together.
    val sailNdkPath = providers.gradleProperty("sail.ndkPath").orNull
    val sailNdkVersion = providers.gradleProperty("sail.ndkVersion").orNull
    require((sailNdkPath == null) == (sailNdkVersion == null)) {
        "pass -Psail.ndkPath and -Psail.ndkVersion together"
    }
    sailNdkPath?.let { ndkPath = it }
    sailNdkVersion?.let { ndkVersion = it }

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            // All four for the release; -Psail.abis=x86_64 for a build of
            // one, as the emulator test's (bindings/kotlin/android-test).
            abiFilters += providers.gradleProperty("sail.abis").orNull
                ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
                ?: listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
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

    // An AAR's libraries keep their debug information: the release pipeline
    // moves it apart (scripts/release/package-aar.sh), where a crash in sail
    // can be read with it; AGP would otherwise strip it and lose it.
    packaging {
        jniLibs {
            keepDebugSymbols += "**/*.so"
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
