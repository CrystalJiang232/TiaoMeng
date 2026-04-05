add_executable(client
    main.cpp
    connection.cpp
    config.cpp
    client.cpp
)

target_include_directories(client PRIVATE ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(client PRIVATE
    Boost::system
    Boost::json
    Threads::Threads
    crypto
    fundamentals
    logger
)

set_target_properties(client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
