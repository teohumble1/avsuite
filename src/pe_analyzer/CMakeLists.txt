add_library(avpe STATIC
    src/pe_analyzer.cpp
    src/authenticode.cpp
)

target_include_directories(avpe PUBLIC include)
target_link_libraries(avpe PUBLIC avcore PRIVATE wintrust crypt32)
