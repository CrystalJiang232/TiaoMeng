add_library(logger STATIC
    logger.cpp
    metrics.cpp
)

target_include_directories(logger PUBLIC
    ${CMAKE_SOURCE_DIR}/include/logger
)

target_link_libraries(logger PUBLIC
    Threads::Threads
)
