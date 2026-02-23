cmake_minimum_required(VERSION 3.25)

project(msg_svr LANGUAGES CXX)

set(MSG_SVR_BUILD_MODE "DEFAULT" CACHE STRING "Build mode: DEFAULT, DEBUG, OPTIMIZE, TEST")
set_property(CACHE MSG_SVR_BUILD_MODE PROPERTY STRINGS DEFAULT DEBUG OPTIMIZE TEST)
string(TOUPPER ${MSG_SVR_BUILD_MODE} MSG_SVR_BUILD_MODE)

if(MSG_SVR_BUILD_MODE STREQUAL "DEBUG")
    set(CMAKE_BUILD_TYPE Debug)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-O0 -g3 -fno-omit-frame-pointer)
        add_compile_options(-fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
        add_compile_options(-Wall -Wextra -Wpedantic)
    endif()
    add_compile_definitions(BOOST_ASIO_ENABLE_HANDLER_TRACKING)

elseif(MSG_SVR_BUILD_MODE STREQUAL "OPTIMIZE")
    set(CMAKE_BUILD_TYPE Release)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-O3 -march=native -mtune=native -flto=auto -ffast-math -funroll-loops)
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")
    endif()
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    add_compile_definitions(BOOST_ASIO_DISABLE_BOOST_COROUTINE BOOST_ASIO_NO_DEPRECATED)

elseif(MSG_SVR_BUILD_MODE STREQUAL "TEST")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
    include(CTest)
    enable_testing()
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-O2 -g)
    endif()
    option(MSG_SVR_COVERAGE "Enable code coverage" OFF)
    if(MSG_SVR_COVERAGE)
        add_compile_options(--coverage)
        add_link_options(--coverage)
    endif()

else()
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-O2 -g -Wall -Wextra)
    endif()
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost 1.82 REQUIRED COMPONENTS system json)
find_package(Threads REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_subdirectory(fundamentals)
add_subdirectory(crypto)
add_subdirectory(logger)
add_subdirectory(server)
add_subdirectory(client)

if(MSG_SVR_BUILD_MODE STREQUAL "TEST")
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.2
    )
    FetchContent_MakeAvailable(Catch2)
    add_subdirectory(tests)
endif()
