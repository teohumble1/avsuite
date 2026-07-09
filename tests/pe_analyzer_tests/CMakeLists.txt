add_executable(avpe_tests
    test_pe_analyzer.cpp
)

target_link_libraries(avpe_tests PRIVATE avpe GTest::gtest GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(avpe_tests)
