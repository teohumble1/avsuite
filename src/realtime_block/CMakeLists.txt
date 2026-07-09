add_library(avrealtimeblock STATIC
    src/minifilter_client.cpp
)

target_include_directories(avrealtimeblock PUBLIC include)
target_link_libraries(avrealtimeblock PRIVATE fltlib)
