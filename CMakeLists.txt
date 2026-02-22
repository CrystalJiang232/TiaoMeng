cmake_minimum_required(VERSION 3.25)

project(msg_svr LANGUAGES CXX)

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

# Note: Hibiscus library has been removed - functionality moved to:
# - fundamentals/  (Msg types, byte utilities, serialization)
# - json_utils.hpp (JSON helper functions)
# - crypto/        (Cryptographic utilities)
