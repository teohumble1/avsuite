add_executable(avrealtime_tests
    test_folder_watcher.cpp
)

target_link_libraries(avrealtime_tests PRIVATE avrealtime GTest::gtest GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(avrealtime_tests)
