add_library(avlogging STATIC
    src/logger.cpp
)

target_include_directories(avlogging PUBLIC include)

find_package(spdlog CONFIG REQUIRED)
target_link_libraries(avlogging PUBLIC spdlog::spdlog)
