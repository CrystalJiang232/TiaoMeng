add_library(logger STATIC
    logger.cpp
)

target_include_directories(logger PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(logger PUBLIC
    Threads::Threads
)
