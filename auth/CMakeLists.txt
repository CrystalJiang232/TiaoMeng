add_library(auth STATIC
    argon2_hasher.cpp
)

target_include_directories(auth PUBLIC ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(auth PUBLIC
    sodium
)
