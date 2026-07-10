add_executable(avbehavior_tests
    test_rule_engine.cpp
    test_benign_corpus.cpp
)

target_link_libraries(avbehavior_tests PRIVATE avbehavior GTest::gtest GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(avbehavior_tests)
