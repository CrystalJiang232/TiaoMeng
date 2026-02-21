add_library(fundamentals STATIC
    msg_serialize.cpp
)

target_include_directories(fundamentals PUBLIC
    ${CMAKE_SOURCE_DIR}/include/fundamentals
)

target_link_libraries(fundamentals PUBLIC
    Boost::json
)
