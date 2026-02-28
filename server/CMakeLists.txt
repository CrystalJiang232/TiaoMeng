find_library(OQS_LIB oqs REQUIRED PATHS /usr/local/lib)
find_package(OpenSSL REQUIRED)

add_executable(server
    main.cpp
    server.cpp
    connection.cpp
    event_handler.cpp
    config.cpp
)

target_include_directories(server PRIVATE /usr/local/include)


target_link_libraries(server
    Boost::system
    Boost::json
    Threads::Threads
    crypto
    fundamentals
    logger
    threadpool
    auth
)

set_target_properties(server PROPERTIES
    OUTPUT_NAME "server"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)