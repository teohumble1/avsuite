add_executable(avstaticscan_tests
    test_hash_signature.cpp
    test_yara_engine.cpp
)

target_link_libraries(avstaticscan_tests PRIVATE avstaticscan GTest::gtest GTest::gtest_main)
target_compile_definitions(avstaticscan_tests PRIVATE
    AVSTATICSCAN_RULES_DIR="${CMAKE_SOURCE_DIR}/src/static_scan/rules"
)

include(GoogleTest)
gtest_discover_tests(avstaticscan_tests)
