add_executable(avregscan_tests
    test_registry_scanner.cpp
)

target_link_libraries(avregscan_tests PRIVATE avregscan GTest::gtest GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(avregscan_tests)
