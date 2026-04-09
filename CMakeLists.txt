cmake_minimum_required(VERSION 3.21)
project(tlsdump C CXX)

set(CMAKE_CXX_STANDARD 23)

add_executable(tlsdump src/main.cpp
        src/DataConsumer.h
        src/PtraceConnectionTracker.h src/PtraceConnectionTracker.cpp
        src/util.h
        src/MemoryExporter.h src/MemoryExporter.cpp
        src/TlsDecryptor.h src/TlsDecryptor.cpp
        src/Direction.h
        src/wireshark.h src/wireshark.c
        src/DataConsumerFactory.h)

find_package(PkgConfig REQUIRED)

pkg_search_module(GLIB REQUIRED glib-2.0)


include_directories(${GLIB_INCLUDE_DIRS})
link_directories(${GLIB_LIBRARY_DIRS})

find_package(Threads REQUIRED)
target_link_libraries(tlsdump ${GLIB_LIBRARIES} gcrypt Threads::Threads)

# Test helper for multi-process/thread tracing tests
pkg_search_module(CURL libcurl)
if(CURL_FOUND)
    add_executable(test_multiprocess tests/test_multiprocess.c)
    target_include_directories(test_multiprocess PRIVATE ${CURL_INCLUDE_DIRS})
    target_link_directories(test_multiprocess PRIVATE ${CURL_LIBRARY_DIRS})
    target_link_libraries(test_multiprocess ${CURL_LIBRARIES} Threads::Threads)
endif()