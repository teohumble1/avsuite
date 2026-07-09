add_library(avremediation STATIC
    src/quarantine.cpp
)

target_include_directories(avremediation PUBLIC include)
target_link_libraries(avremediation PUBLIC avcore avstorage)
