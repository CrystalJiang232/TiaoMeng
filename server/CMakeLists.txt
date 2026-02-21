find_library(OQS_LIB oqs REQUIRED PATHS /usr/local/lib)
find_package(OpenSSL REQUIRED)

add_executable(server
    main.cpp
    server.cpp
    connection.cpp
    msg.cpp
    cipher.cpp
    event_handler.cpp
)

target_include_directories(server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server PRIVATE /usr/local/include)


target_link_libraries(server
    Boost::system
    Boost::json
    Threads::Threads
    ${OQS_LIB}
    OpenSSL::Crypto
    Hibiscus
)

set_target_properties(server PROPERTIES
    OUTPUT_NAME "server"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)