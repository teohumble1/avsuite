add_library(avrealtime STATIC
    src/folder_watcher.cpp
)

target_include_directories(avrealtime PUBLIC include)
