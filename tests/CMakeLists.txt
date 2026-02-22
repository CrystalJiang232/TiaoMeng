add_executable(test_fundamentals
    test_fundamentals.cpp
)

target_include_directories(test_fundamentals PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_fundamentals
    fundamentals
    Catch2::Catch2WithMain
)

add_executable(test_crypto
    test_crypto.cpp
)

target_include_directories(test_crypto PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    /usr/local/include
)

target_link_libraries(test_crypto
    crypto
    fundamentals
    Catch2::Catch2WithMain
)

add_executable(test_config
    test_config.cpp
    ${CMAKE_SOURCE_DIR}/server/config.cpp
)

target_include_directories(test_config PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_config
    logger
    Boost::json
    Catch2::Catch2WithMain
)

include(Catch)
catch_discover_tests(test_fundamentals)
catch_discover_tests(test_crypto)
catch_discover_tests(test_config)
