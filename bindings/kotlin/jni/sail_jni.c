/*
 * sail's C ABI for the JVM (Android, and a desktop JVM for tests): what
 * io.github.peakpassvpn.sail.Native declares, each a call of sail.h.
 *
 * - A call that fails throws SailException(code, message).
 * - Callbacks run on sail's threads; each attaches to the JVM the first
 *   time and detaches when the thread ends.
 * - The Kotlin objects sail calls back are held as global references,
 *   deleted when sail releases their context.
 */

#include <jni.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sail.h"

static JavaVM *vm;
static pthread_key_t attached;
static jclass exception_class;
static jmethodID exception_init;
static jmethodID on_event;
static jmethodID on_release;
static jmethodID protect_socket;
static jmethodID open_tun;
static jmethodID service_stop;
static jmethodID service_reload;
static jmethodID find_owner;

static void detach(void *unused) {
    (void)unused;
    (*vm)->DetachCurrentThread(vm);
}

/* The JNIEnv of this thread, attached when it is one of sail's. */
static JNIEnv *env_here(void) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) {
        return env;
    }
#ifdef __ANDROID__
    if ((*vm)->AttachCurrentThreadAsDaemon(vm, &env, NULL) != JNI_OK) {
#else
    if ((*vm)->AttachCurrentThreadAsDaemon(vm, (void **)&env, NULL) != JNI_OK) {
#endif
        return NULL;
    }
    pthread_setspecific(attached, (void *)1);
    return env;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *jvm, void *reserved) {
    (void)reserved;
    vm = jvm;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    pthread_key_create(&attached, detach);
    jclass local = (*env)->FindClass(env, "io/github/peakpassvpn/sail/SailException");
    if (local == NULL) return JNI_ERR;
    exception_class = (*env)->NewGlobalRef(env, local);
    exception_init = (*env)->GetMethodID(env, exception_class, "<init>", "(ILjava/lang/String;)V");
    jclass sink = (*env)->FindClass(env, "io/github/peakpassvpn/sail/EventSink");
    if (sink == NULL) return JNI_ERR;
    on_event = (*env)->GetMethodID(env, sink, "onEvent", "(ILjava/lang/String;)V");
    on_release = (*env)->GetMethodID(env, sink, "onRelease", "()V");
    jclass platform = (*env)->FindClass(env, "io/github/peakpassvpn/sail/PlatformBridge");
    if (platform == NULL) return JNI_ERR;
    protect_socket = (*env)->GetMethodID(env, platform, "protectSocket", "(I)Z");
    open_tun = (*env)->GetMethodID(env, platform, "openTun", "(Ljava/lang/String;)I");
    service_stop = (*env)->GetMethodID(env, platform, "serviceStop", "()I");
    service_reload = (*env)->GetMethodID(env, platform, "serviceReload", "()I");
    find_owner = (*env)->GetMethodID(env, platform, "findConnectionOwner", "(Ljava/lang/String;)Ljava/lang/String;");
    return JNI_VERSION_1_6;
}

/* Throws what a call failed with, freeing its message; whether it did. */
static int failed(JNIEnv *env, int32_t code, char *err) {
    if (code == SAIL_OK) {
        return 0;
    }
    jstring message = (*env)->NewStringUTF(env, err ? err : "");
    sail_free_string(err);
    jobject exception = (*env)->NewObject(env, exception_class, exception_init, (jint)code, message);
    (*env)->Throw(env, (jthrowable)exception);
    return 1;
}

/* A Java string as C, for the call; NULL for null. */
static const char *c_string(JNIEnv *env, jstring s) {
    return s ? (*env)->GetStringUTFChars(env, s, NULL) : NULL;
}

static void done(JNIEnv *env, jstring s, const char *c) {
    if (s) (*env)->ReleaseStringUTFChars(env, s, c);
}

/* sail's string as Java, freeing it. */
static jstring take(JNIEnv *env, char *out) {
    jstring s = (*env)->NewStringUTF(env, out ? out : "");
    sail_free_string(out);
    return s;
}

/* Platform callbacks: the context is a global reference to the bridge. */

static void platform_release(void *context) {
    JNIEnv *env = env_here();
    if (env) (*env)->DeleteGlobalRef(env, (jobject)context);
}

static bool platform_protect(int32_t fd, void *context) {
    JNIEnv *env = env_here();
    if (!env) return false;
    jboolean ok = (*env)->CallBooleanMethod(env, (jobject)context, protect_socket, (jint)fd);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return false;
    }
    return ok;
}

static int32_t platform_open_tun(const char *request, void *context) {
    JNIEnv *env = env_here();
    if (!env) return -1;
    jstring json = (*env)->NewStringUTF(env, request);
    jint fd = (*env)->CallIntMethod(env, (jobject)context, open_tun, json);
    (*env)->DeleteLocalRef(env, json);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return -1;
    }
    return fd;
}

static int32_t platform_service(void *context, jmethodID method) {
    JNIEnv *env = env_here();
    if (!env) return SAIL_ERR_INTERNAL;
    jint code = (*env)->CallIntMethod(env, (jobject)context, method);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return SAIL_ERR_INTERNAL;
    }
    return code;
}

/* Who opened a connection: the bridge's JSON, into sail's buffer; minus
 * what it needs when the buffer is too small, 0 when it cannot tell. */
static ptrdiff_t platform_find_owner(const char *query, char *out, size_t out_len, void *context) {
    JNIEnv *env = env_here();
    if (!env) return 0;
    jstring q = (*env)->NewStringUTF(env, query);
    jstring reply = (jstring)(*env)->CallObjectMethod(env, (jobject)context, find_owner, q);
    (*env)->DeleteLocalRef(env, q);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return 0;
    }
    if (!reply) return 0;
    const char *json = (*env)->GetStringUTFChars(env, reply, NULL);
    size_t len = strlen(json);
    ptrdiff_t written;
    if (len > out_len) {
        written = -(ptrdiff_t)len;
    } else {
        memcpy(out, json, len);
        written = (ptrdiff_t)len;
    }
    (*env)->ReleaseStringUTFChars(env, reply, json);
    (*env)->DeleteLocalRef(env, reply);
    return written;
}

static int32_t platform_stop(void *context) { return platform_service(context, service_stop); }
static int32_t platform_reload(void *context) { return platform_service(context, service_reload); }

/* Event callbacks: the context is a global reference to the sink. */

static void event(uint32_t kind, const char *json, void *context) {
    JNIEnv *env = env_here();
    if (!env) return;
    jstring s = (*env)->NewStringUTF(env, json);
    (*env)->CallVoidMethod(env, (jobject)context, on_event, (jint)kind, s);
    (*env)->DeleteLocalRef(env, s);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
}

static void event_release(void *context) {
    JNIEnv *env = env_here();
    if (!env) return;
    (*env)->CallVoidMethod(env, (jobject)context, on_release);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->DeleteGlobalRef(env, (jobject)context);
}

#define NATIVE(name) Java_io_github_peakpassvpn_sail_Native_##name

JNIEXPORT jlong JNICALL NATIVE(instanceNew)(JNIEnv *env, jclass cls, jstring settings, jobject bridge,
                                            jboolean protect, jboolean tun, jboolean stop, jboolean reload,
                                            jboolean owner) {
    (void)cls;
    SailPlatform platform;
    memset(&platform, 0, sizeof platform);
    platform.struct_size = sizeof platform;
    if (bridge) {
        platform.context = (*env)->NewGlobalRef(env, bridge);
        platform.release = platform_release;
        if (protect) platform.protect_socket = platform_protect;
        if (tun) platform.open_tun = platform_open_tun;
        if (stop) platform.service_stop = platform_stop;
        if (reload) platform.service_reload = platform_reload;
        if (owner) platform.find_connection_owner = platform_find_owner;
    }
    const char *s = c_string(env, settings);
    SailInstance instance = 0;
    char *err = NULL;
    int32_t code = sail_instance_new(s, &platform, &instance, &err);
    done(env, settings, s);
    if (code != SAIL_OK && platform.context) {
        /* A call that fails takes nothing of the context. */
        (*env)->DeleteGlobalRef(env, (jobject)platform.context);
    }
    failed(env, code, err);
    return (jlong)instance;
}

JNIEXPORT jlong JNICALL NATIVE(clientConnect)(JNIEnv *env, jclass cls, jstring options) {
    (void)cls;
    const char *o = c_string(env, options);
    SailInstance client = 0;
    char *err = NULL;
    int32_t code = sail_client_connect(o, &client, &err);
    done(env, options, o);
    failed(env, code, err);
    return (jlong)client;
}

JNIEXPORT void JNICALL NATIVE(instanceFree)(JNIEnv *env, jclass cls, jlong instance) {
    (void)env;
    (void)cls;
    sail_instance_free((SailInstance)instance);
}

/* A call taking one optional string and nothing else back. */
#define STRING_CALL(name, function)                                                       \
    JNIEXPORT void JNICALL NATIVE(name)(JNIEnv *env, jclass cls, jlong h, jstring arg) {  \
        (void)cls;                                                                        \
        const char *a = c_string(env, arg);                                               \
        char *err = NULL;                                                                 \
        int32_t code = function((SailInstance)h, a, &err);                                \
        done(env, arg, a);                                                                \
        failed(env, code, err);                                                           \
    }

STRING_CALL(instanceStart, sail_instance_start)
STRING_CALL(instanceStartFile, sail_instance_start_file)
STRING_CALL(instanceReload, sail_instance_reload)
STRING_CALL(instanceServe, sail_instance_serve)
STRING_CALL(setMode, sail_set_mode)
STRING_CALL(setNetworkState, sail_set_network_state)
STRING_CALL(updateProvider, sail_update_provider)
STRING_CALL(updateRuleSet, sail_update_rule_set)

/* A call answering JSON. */
#define JSON_CALL(name, function)                                             \
    JNIEXPORT jstring JNICALL NATIVE(name)(JNIEnv *env, jclass cls, jlong h) { \
        (void)cls;                                                            \
        char *out = NULL;                                                     \
        char *err = NULL;                                                     \
        if (failed(env, function((SailInstance)h, &out, &err), err)) return NULL; \
        return take(env, out);                                                \
    }

JSON_CALL(instanceState, sail_instance_state)
JSON_CALL(instanceCapabilities, sail_instance_capabilities)
JSON_CALL(traffic, sail_traffic)
JSON_CALL(connections, sail_connections)
JSON_CALL(outbounds, sail_outbounds)
JSON_CALL(groups, sail_groups)
JSON_CALL(mode, sail_mode)
JSON_CALL(providers, sail_providers)
JSON_CALL(ruleSets, sail_rule_sets)

JNIEXPORT jstring JNICALL NATIVE(capabilities)(JNIEnv *env, jclass cls) {
    (void)cls;
    char *out = NULL;
    char *err = NULL;
    if (failed(env, sail_capabilities(&out, &err), err)) return NULL;
    return take(env, out);
}

JNIEXPORT void JNICALL NATIVE(instanceStop)(JNIEnv *env, jclass cls, jlong h, jint timeout_ms) {
    (void)cls;
    char *err = NULL;
    failed(env, sail_instance_stop((SailInstance)h, (uint32_t)timeout_ms, &err), err);
}

JNIEXPORT jboolean JNICALL NATIVE(closeConnection)(JNIEnv *env, jclass cls, jlong h, jlong id) {
    (void)cls;
    bool closed = false;
    char *err = NULL;
    failed(env, sail_close_connection((SailInstance)h, (uint64_t)id, &closed, &err), err);
    return closed;
}

JNIEXPORT jlong JNICALL NATIVE(closeAllConnections)(JNIEnv *env, jclass cls, jlong h) {
    (void)cls;
    uint64_t count = 0;
    char *err = NULL;
    failed(env, sail_close_all_connections((SailInstance)h, &count, &err), err);
    return (jlong)count;
}

JNIEXPORT jint JNICALL NATIVE(dial)(JNIEnv *env, jclass cls, jlong h, jstring outbound, jstring network,
                                    jstring host, jint port, jint timeout_ms) {
    (void)cls;
    const char *o = c_string(env, outbound);
    const char *n = c_string(env, network);
    const char *a = c_string(env, host);
    int32_t fd = -1;
    char *err = NULL;
    int32_t code = sail_dial((SailInstance)h, o, n, a, (uint16_t)port, (uint32_t)timeout_ms, &fd, &err);
    done(env, outbound, o);
    done(env, network, n);
    done(env, host, a);
    failed(env, code, err);
    return fd;
}

JNIEXPORT void JNICALL NATIVE(select)(JNIEnv *env, jclass cls, jlong h, jstring group, jstring member) {
    (void)cls;
    const char *g = c_string(env, group);
    const char *m = c_string(env, member);
    char *err = NULL;
    int32_t code = sail_select((SailInstance)h, g, m, &err);
    done(env, group, g);
    done(env, member, m);
    failed(env, code, err);
}

JNIEXPORT jlong JNICALL NATIVE(delay)(JNIEnv *env, jclass cls, jlong h, jstring tag, jstring url, jint timeout_ms) {
    (void)cls;
    const char *t = c_string(env, tag);
    const char *u = c_string(env, url);
    uint64_t delay = 0;
    char *err = NULL;
    int32_t code = sail_delay((SailInstance)h, t, u, (uint32_t)timeout_ms, &delay, &err);
    done(env, tag, t);
    done(env, url, u);
    failed(env, code, err);
    return (jlong)delay;
}

JNIEXPORT jlong JNICALL NATIVE(urlTest)(JNIEnv *env, jclass cls, jlong h, jstring tag, jstring url, jint timeout_ms) {
    (void)cls;
    const char *t = c_string(env, tag);
    const char *u = c_string(env, url);
    uint64_t operation = 0;
    char *err = NULL;
    int32_t code = sail_url_test((SailInstance)h, t, u, (uint32_t)timeout_ms, &operation, &err);
    done(env, tag, t);
    done(env, url, u);
    failed(env, code, err);
    return (jlong)operation;
}

JNIEXPORT void JNICALL NATIVE(cancel)(JNIEnv *env, jclass cls, jlong operation) {
    (void)cls;
    char *err = NULL;
    failed(env, sail_cancel((SailOperation)operation, &err), err);
}

JNIEXPORT void JNICALL NATIVE(networkChanged)(JNIEnv *env, jclass cls, jlong h, jint mtu) {
    (void)cls;
    char *err = NULL;
    failed(env, sail_network_changed((SailInstance)h, (uint16_t)mtu, &err), err);
}

JNIEXPORT void JNICALL NATIVE(clearLogs)(JNIEnv *env, jclass cls, jlong h) {
    (void)cls;
    char *err = NULL;
    failed(env, sail_clear_logs((SailInstance)h, &err), err);
}

JNIEXPORT jlong JNICALL NATIVE(subscribe)(JNIEnv *env, jclass cls, jlong h, jint kind, jstring options, jobject sink) {
    (void)cls;
    jobject context = (*env)->NewGlobalRef(env, sink);
    const char *o = c_string(env, options);
    SailSubscription subscription = 0;
    char *err = NULL;
    int32_t code = sail_subscribe((SailInstance)h, (uint32_t)kind, o, event, context, event_release, &subscription, &err);
    done(env, options, o);
    if (code != SAIL_OK) {
        /* A call that fails takes nothing of the context. */
        (*env)->DeleteGlobalRef(env, context);
    }
    failed(env, code, err);
    return (jlong)subscription;
}

JNIEXPORT void JNICALL NATIVE(unsubscribe)(JNIEnv *env, jclass cls, jlong subscription) {
    (void)env;
    (void)cls;
    /* Ended already is no harm. */
    sail_unsubscribe((SailSubscription)subscription, NULL);
}
