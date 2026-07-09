find_package(httplib CONFIG REQUIRED)

add_executable(avupdateserver
    src/main.cpp
)

target_link_libraries(avupdateserver PRIVATE avstorage avstaticscan avcore httplib::httplib)
