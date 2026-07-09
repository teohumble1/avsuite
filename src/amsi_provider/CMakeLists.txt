add_library(avamsi SHARED
    src/dllmain.cpp
    src/amsi_provider.cpp
)

target_include_directories(avamsi PRIVATE src)
target_link_libraries(avamsi PRIVATE avstaticscan avcore amsi)
target_compile_options(avamsi PRIVATE /EHsc)

# After build, copy a 'rules' subfolder next to the DLL so DllRegisterServer
# finds the YARA rules at the same location as the DLL.
add_custom_command(TARGET avamsi POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${AVSTATICSCAN_RULES_SOURCE_DIR}"
        "$<TARGET_FILE_DIR:avamsi>/rules"
    COMMENT "Copying YARA rules next to avamsi.dll"
)
