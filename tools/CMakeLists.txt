add_executable(user_admin user_admin.cpp)

target_include_directories(user_admin PRIVATE ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(user_admin PRIVATE
    auth
    threadpool
)
