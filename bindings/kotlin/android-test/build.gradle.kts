// The app sail runs in, as a host's would: a VpnService that opens the TUN
// sail asks for and protects its sockets (src/main), and the tests that
// start it and send through it (src/androidTest).

plugins {
    id("com.android.application")
}

android {
    namespace = "io.github.peakpassvpn.sail.test"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.peakpassvpn.sail.test"
        minSdk = 29
        targetSdk = 36
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":sail"))
    // The binding's flows of events, which the tests collect.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("junit:junit:4.13.2")
}
