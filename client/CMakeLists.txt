add_executable(client
    main.cpp
    client.cpp
)

target_include_directories(client PRIVATE ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(client PRIVATE
    Boost::system
    Boost::json
    Threads::Threads
    crypto
    fundamentals
)
