add_library(avengine STATIC
    src/engine.cpp
)

# MSVC 14.44 (VS 2022 17.14) ICE when httplib.h + nlohmann/json.hpp are both
# instantiated under /O2 in the same TU.  Drop to /Od for this file only.
if(MSVC)
    set_source_files_properties(src/engine.cpp PROPERTIES COMPILE_FLAGS "/Od")
endif()

target_include_directories(avengine PUBLIC include)

find_package(httplib CONFIG REQUIRED)

target_link_libraries(avengine PUBLIC
    avcore
    avstorage
    avremediation
    avstaticscan
    avpe
    avregscan
    avbehavior
    avrealtime
    avrealtimeblock
    avetw
    httplib::httplib
)
