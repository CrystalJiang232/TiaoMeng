add_library(threadpool STATIC threadpool.cpp)

target_include_directories(threadpool PUBLIC ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(threadpool PUBLIC Boost::system Threads::Threads)
