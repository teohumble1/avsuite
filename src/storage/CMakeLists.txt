add_library(avstorage STATIC
    src/database.cpp
)

target_include_directories(avstorage PUBLIC include)
target_link_libraries(avstorage PUBLIC avcore)

find_package(unofficial-sqlite3 CONFIG REQUIRED)
target_link_libraries(avstorage PRIVATE unofficial::sqlite3::sqlite3)
