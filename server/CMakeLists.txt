add_executable(server
    main.cpp
    server.cpp
    connection.cpp
    msg.cpp
    router.cpp
)

target_include_directories(server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(server
    Boost::system
    Threads::Threads
)

set_target_properties(server PROPERTIES
    OUTPUT_NAME "server"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)