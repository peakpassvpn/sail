# What jni/sail_jni.c reaches by name, which an app's R8 must leave as it
# is.

# The native methods: the C side's Java_io_github_peakpassvpn_sail_Native_*.
-keep class io.github.peakpassvpn.sail.Native {
    native <methods>;
}

# Classes found with FindClass and methods with GetMethodID (JNI_OnLoad).
-keep class io.github.peakpassvpn.sail.SailException {
    <init>(int, java.lang.String);
}
-keep class io.github.peakpassvpn.sail.EventSink {
    void onEvent(int, java.lang.String);
    void onRelease();
}
-keep class io.github.peakpassvpn.sail.PlatformBridge {
    boolean protectSocket(int);
    int openTun(java.lang.String);
    int serviceStop();
    int serviceReload();
    java.lang.String findConnectionOwner(java.lang.String);
}

# The JSON models: kotlinx.serialization's own rules keep their
# serializers; these keep the models' names for the generated ones.
-keep,includedescriptorclasses class io.github.peakpassvpn.sail.**$$serializer { *; }
-keepclassmembers class io.github.peakpassvpn.sail.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}
