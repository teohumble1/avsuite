find_package(llama CONFIG REQUIRED)

add_library(avai STATIC
    src/llm_assistant.cpp
)

target_include_directories(avai PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(avai PUBLIC llama)

# llama.cpp needs C++17 at minimum; our project is already on C++20
target_compile_features(avai PUBLIC cxx_std_20)

# Suppress llama.cpp's own W4 warnings bleeding into our build
if(MSVC)
    target_compile_options(avai PRIVATE /W3)
endif()
