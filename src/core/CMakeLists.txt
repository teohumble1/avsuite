add_library(avcore STATIC
    src/config.cpp
    src/path_utils.cpp
    src/base64.cpp
)

target_include_directories(avcore PUBLIC include)

find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(avcore PUBLIC nlohmann_json::nlohmann_json)
