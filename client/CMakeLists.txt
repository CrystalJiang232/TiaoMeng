find_library(OQS_LIB oqs REQUIRED PATHS /usr/local/lib)
find_package(OpenSSL REQUIRED)

add_executable(client
    main.cpp
    client.cpp
)

target_include_directories(client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(client PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(client PRIVATE /usr/local/include)

target_link_libraries(client
    Boost::system
    Boost::json
    Threads::Threads
    crypto
    fundamentals
)

set_target_properties(client PROPERTIES
    OUTPUT_NAME "client"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
