add_library(avbehavior STATIC
    src/process_tree.cpp
    src/rule_engine.cpp
    # Original rules
    src/rules/rule_temp_appdata_spawn.cpp
    src/rules/rule_suspicious_parent_child.cpp
    src/rules/rule_unsigned_temp_exec.cpp
    src/rules/rule_lolbin_susp_args.cpp
    src/rules/rule_av_killer_child.cpp
    # Extended detection coverage
    src/rules/rule_powershell_obfuscation.cpp
    src/rules/rule_shadow_copy_delete.cpp
    src/rules/rule_credential_access.cpp
    src/rules/rule_lateral_movement.cpp
    src/rules/rule_persistence_registry.cpp
    src/rules/rule_wmi_execution.cpp
    src/rules/rule_scheduled_task_abuse.cpp
    src/rules/rule_service_installation.cpp
    src/rules/rule_amsi_etw_bypass.cpp
    src/rules/rule_ransomware_indicator.cpp
    src/rules/rule_defense_evasion.cpp
    src/rules/rule_malware_behaviors.cpp
    src/rules/rule_cryptominer.cpp
)

target_include_directories(avbehavior
    PUBLIC include
    PRIVATE src
)

target_link_libraries(avbehavior PUBLIC avcore PRIVATE avpe)
