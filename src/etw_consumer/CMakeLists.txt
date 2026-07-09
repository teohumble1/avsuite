add_library(avetw STATIC
    src/etw_session.cpp
    src/dns_etw_session.cpp
)

target_include_directories(avetw
    PUBLIC include
    PRIVATE ${CMAKE_SOURCE_DIR}/third_party/krabsetw/krabs
)

target_link_libraries(avetw PUBLIC avbehavior)

# krabsetw assumes UNICODE/_UNICODE are defined (it uses TCHAR-style macros
# like TEXT()/KERNEL_LOGGER_NAME internally, e.g. in kt.hpp) -- Visual Studio
# project templates define these by default, but a from-scratch CMake target
# doesn't. Scoped to this target only; the rest of the codebase calls the
# explicit "A"-suffixed Win32 functions directly, so this has no effect there.
target_compile_definitions(avetw PRIVATE UNICODE _UNICODE)

# krabsetw is header-only and self-links advapi32/ole32/tdh/comsuppw via
# #pragma comment(lib, ...) in its own headers -- nothing extra needed here.
if(MSVC)
    target_compile_options(avetw PRIVATE /wd4996)
endif()
