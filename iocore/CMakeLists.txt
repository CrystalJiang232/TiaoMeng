cmake_minimum_required(VERSION 3.25)

set(IOCORE_SOURCES
    context_pool.cpp
)

# Platform-specific sources
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND IOCORE_SOURCES platform/affinity_linux.cpp)
    set(IOCORE_PLATFORM_DEFS HAS_SO_REUSEPORT)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND IOCORE_SOURCES platform/affinity_macos.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND IOCORE_SOURCES platform/affinity_windows.cpp)
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

add_library(iocore STATIC ${IOCORE_SOURCES})

target_include_directories(iocore PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(iocore PUBLIC
    Boost::system
    fundamentals
    logger
)

target_compile_definitions(iocore PRIVATE ${IOCORE_PLATFORM_DEFS})

set_target_properties(iocore PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
)
