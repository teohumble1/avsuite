add_library(avstaticscan STATIC
    src/hash_signature.cpp
    src/yara_engine.cpp
)

target_include_directories(avstaticscan PUBLIC include)
target_link_libraries(avstaticscan PUBLIC avcore avstorage PRIVATE bcrypt)

# hash_signature.cpp and yara_engine.cpp share one project PDB; without /FS,
# MSBuild compiling them in parallel intermittently hits C1033 (cannot open
# program database) as both cl.exe instances race to write it.
if(MSVC)
    target_compile_options(avstaticscan PRIVATE /FS)
endif()

# The vcpkg "yara" port does not ship a CMake config (no find_package target),
# so it has to be located manually -- see https://github.com/microsoft/vcpkg/issues/17427
find_path(YARA_INCLUDE_DIR yara.h)
find_library(YARA_LIBRARY NAMES yara libyara)
if(NOT YARA_INCLUDE_DIR OR NOT YARA_LIBRARY)
    message(FATAL_ERROR "libyara not found -- did you run 'vcpkg install' with this project's vcpkg.json manifest?")
endif()

target_include_directories(avstaticscan PRIVATE ${YARA_INCLUDE_DIR})
target_link_libraries(avstaticscan PRIVATE ${YARA_LIBRARY})

# This vcpkg build of libyara has its authenticode/certificate/hash modules
# built against OpenSSL (EVP_*, PKCS7_*, X509_* symbols) -- link it PUBLIC so
# the dependency reaches whatever final executable links avstaticscan, since
# a static library doesn't carry its own dependencies' symbols.
find_package(OpenSSL REQUIRED)
target_link_libraries(avstaticscan PUBLIC OpenSSL::Crypto)

# Exposed so consuming executables (host_console) can copy these starter
# rules next to their own output -- a static lib's own output directory
# isn't necessarily where the final .exe ends up.
set(AVSTATICSCAN_RULES_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rules CACHE INTERNAL "")
