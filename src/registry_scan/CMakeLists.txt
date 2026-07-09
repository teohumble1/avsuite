add_library(avregscan STATIC
    src/registry_scanner.cpp
)

target_include_directories(avregscan PUBLIC include)
target_link_libraries(avregscan PUBLIC avcore PRIVATE avpe advapi32)
