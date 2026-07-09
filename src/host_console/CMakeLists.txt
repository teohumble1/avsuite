add_executable(avconsolehost
    src/main.cpp
)

target_link_libraries(avconsolehost PRIVATE avengine avlogging avcore)

# Ship the starter .yar rules next to this executable so YaraEngine::LoadRules
# finds them at runtime via the exe-relative path resolved in main.cpp.
add_custom_command(TARGET avconsolehost POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${AVSTATICSCAN_RULES_SOURCE_DIR}
        $<TARGET_FILE_DIR:avconsolehost>/yara_rules
)
