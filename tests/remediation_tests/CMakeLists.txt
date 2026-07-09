add_executable(avremediation_tests
    test_quarantine.cpp
)

target_link_libraries(avremediation_tests PRIVATE avremediation GTest::gtest GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(avremediation_tests)
