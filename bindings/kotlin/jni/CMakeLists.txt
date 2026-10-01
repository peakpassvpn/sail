# libsail_jni for one Android ABI: jni/sail_jni.c and sail-ffi's static
# library (libsail.a) linked into one library, which Sail.kt loads as
# "sail_jni". Built by the android/ module's externalNativeBuild.
#
#   SAIL_LIB_DIR      a directory holding <ABI>/libsail.a
#   SAIL_INCLUDE_DIR  the directory holding sail.h (sail-ffi/include)
#
# btls links the C++ runtime: the module passes ANDROID_STL=c++_static, so
# the AAR carries no libc++_shared.so.
cmake_minimum_required(VERSION 3.22)
project(sail_jni C)

if(NOT SAIL_LIB_DIR OR NOT SAIL_INCLUDE_DIR)
    message(FATAL_ERROR "set SAIL_LIB_DIR and SAIL_INCLUDE_DIR")
endif()

add_library(sail STATIC IMPORTED)
set_target_properties(sail PROPERTIES IMPORTED_LOCATION ${SAIL_LIB_DIR}/${ANDROID_ABI}/libsail.a)

add_library(sail_jni SHARED ${CMAKE_CURRENT_SOURCE_DIR}/sail_jni.c)
target_include_directories(sail_jni PRIVATE ${SAIL_INCLUDE_DIR})
target_compile_options(sail_jni PRIVATE -Wall -Werror)
target_link_libraries(sail_jni PRIVATE sail log dl m)
# Only JNI_OnLoad and the Java_… functions are exported: sail_* and
# btls's symbols stay inside, so a host linking another BoringSSL does not
# collide with them.
target_link_options(sail_jni PRIVATE -Wl,--gc-sections -Wl,--exclude-libs,ALL)
