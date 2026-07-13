find_package(Qt6 COMPONENTS Widgets REQUIRED)

set(CMAKE_AUTOMOC ON)

# Every dashboard "page" translation unit -- kept as one list so the ICE
# workaround below (and any future per-file property) applies uniformly
# instead of drifting out of sync with add_executable's source list, which is
# what happened before: this file only listed the original 9 pages while 15+
# more had been added straight to the generated .vcxproj by hand across many
# sessions. A reconfigure (e.g. from any CMakeLists.txt edit elsewhere in the
# tree, which retriggers CMake's ZERO_CHECK) regenerates .vcxproj from THIS
# file and silently dropped every hand-added page. Keep this list authoritative.
set(AVDASHBOARD_PAGE_SOURCES
    src/main_window.cpp
    src/main_window_ai.cpp
    src/main_window_ai_agent.cpp
    src/main_window_alerts.cpp
    src/main_window_autohunt.cpp
    src/main_window_cicd.cpp
    src/main_window_dllintel.cpp
    src/main_window_dlp.cpp
    src/main_window_fingerprint.cpp
    src/main_window_firewall.cpp
    src/main_window_hiddenhunt.cpp
    src/main_window_history.cpp
    src/main_window_hookhunt.cpp
    src/main_window_kernelbios.cpp
    src/main_window_lanmonitor.cpp
    src/main_window_memhunt.cpp
    src/main_window_netguard.cpp
    src/main_window_network.cpp
    src/main_window_osint.cpp
    src/main_window_selfupdate.cpp
    src/main_window_settings.cpp
    src/main_window_supplychain.cpp
    src/main_window_suricata.cpp
    src/main_window_syswatch.cpp
    src/main_window_telemetry.cpp
    src/main_window_webguard.cpp
    src/main_window_threatintel.cpp
    src/main_window_timeline.cpp
    src/main_window_vpn.cpp
    src/main_window_waf.cpp
    src/main_window_wificsi.cpp
)

add_executable(avdashboard WIN32
    src/main.cpp
    src/perf_mode.cpp
    ${AVDASHBOARD_PAGE_SOURCES}
    src/main_window.hpp
    src/perf_mode.hpp
    app.rc
)

target_link_libraries(avdashboard PRIVATE avengine avai avlogging avcore Qt6::Widgets Qt6::EntryPointPrivate)

# MSVC 14.44 ICE with complex Qt+template headers under the project's default
# /std:c++20 -- every page TU is pinned to c++17 instead. main.cpp is
# deliberately left on the project default since it doesn't hit the ICE.
if(MSVC)
    # /Od: disable optimizations (prevents the base MSVC 14.44 ICE on Qt+templates)
    # /bigobj: allow >65535 COFF sections (large TU)
    # /Zm300: triple the default compiler heap (reduces template-depth ICEs)
    set_source_files_properties(${AVDASHBOARD_PAGE_SOURCES}
        PROPERTIES COMPILE_FLAGS "/Od /bigobj /Zm300 /std:c++17")
endif()

# Runtime window/taskbar icon (main.cpp loads it via setWindowIcon; the .rc
# above only covers the exe file icon in Explorer).
add_custom_command(TARGET avdashboard POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/resources/app_icon.png
        $<TARGET_FILE_DIR:avdashboard>/app_icon.png
)

# Ship the starter .yar rules next to this executable, same as host_console.
add_custom_command(TARGET avdashboard POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${AVSTATICSCAN_RULES_SOURCE_DIR}
        $<TARGET_FILE_DIR:avdashboard>/yara_rules
)

# Ship the privacy hardening scripts next to the exe. The Telemetry Guard and
# Fingerprint Guard tabs' Apply buttons run these elevated from the exe's own
# directory (ScriptPath()), so they must sit beside avdashboard.exe.
add_custom_command(TARGET avdashboard POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/scripts/Harden-Telemetry.ps1
        ${CMAKE_SOURCE_DIR}/scripts/Harden-Fingerprint.ps1
        ${CMAKE_SOURCE_DIR}/scripts/Harden-WebGuard.ps1
        $<TARGET_FILE_DIR:avdashboard>
)

# Qt's platform plugin (qwindows.dll) is loaded dynamically at runtime, so
# vcpkg's automatic dependency-copying (which only follows direct link
# dependencies) won't bring it along -- copy it explicitly. vcpkg mirrors the
# whole release tree under a debug/ subfolder for debug binaries, e.g.:
#   <installed>/x64-windows/Qt6/plugins/platforms/qwindows.dll        (release)
#   <installed>/x64-windows/debug/Qt6/plugins/platforms/qwindowsd.dll (debug)
set(_vcpkg_installed_root "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}")
add_custom_command(TARGET avdashboard POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:avdashboard>/platforms
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${_vcpkg_installed_root}/$<$<CONFIG:Debug>:debug/>Qt6/plugins/platforms/qwindows$<$<CONFIG:Debug>:d>.dll"
        $<TARGET_FILE_DIR:avdashboard>/platforms/
)
