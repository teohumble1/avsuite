#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include "avrealtime/folder_watcher.hpp"

namespace {

class CallbackWaiter {
public:
    void OnChange(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        paths_.push_back(path);
        cv_.notify_all();
    }

    bool WaitForAtLeast(size_t count, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, timeout, [&] { return paths_.size() >= count; });
    }

    std::vector<std::string> Paths() {
        std::lock_guard<std::mutex> lock(mutex_);
        return paths_;
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::string> paths_;
};

} // namespace

TEST(FolderWatcherTest, FiresCallbackOnNewFile) {
    const auto watch_dir = std::filesystem::temp_directory_path() / "avsuite_watch_test_new_file";
    std::filesystem::remove_all(watch_dir);
    std::filesystem::create_directories(watch_dir);

    CallbackWaiter waiter;
    avrealtime::FolderWatcher watcher({watch_dir.string()}, [&](const std::string& p) { waiter.OnChange(p); }, 200);
    watcher.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // let the watch thread arm before we write

    const auto file_path = watch_dir / "dropped_file.txt";
    {
        std::ofstream out(file_path);
        out << "benign synthetic content for the watcher test";
    }

    EXPECT_TRUE(waiter.WaitForAtLeast(1, std::chrono::seconds(5)));

    watcher.Stop();
    std::filesystem::remove_all(watch_dir);
}

TEST(FolderWatcherTest, SuppressesRepeatedEventsWithinDebounceWindow) {
    const auto watch_dir = std::filesystem::temp_directory_path() / "avsuite_watch_test_debounce";
    std::filesystem::remove_all(watch_dir);
    std::filesystem::create_directories(watch_dir);

    CallbackWaiter waiter;
    avrealtime::FolderWatcher watcher({watch_dir.string()}, [&](const std::string& p) { waiter.OnChange(p); }, 2000);
    watcher.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto file_path = watch_dir / "rewritten_file.txt";
    for (int i = 0; i < 5; ++i) {
        std::ofstream out(file_path, std::ios::app);
        out << "chunk " << i << "\n";
        out.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    ASSERT_TRUE(waiter.WaitForAtLeast(1, std::chrono::seconds(5)));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    // The 2-second debounce window should have suppressed the later writes in
    // the burst, so a single callback is expected despite 5 writes.
    EXPECT_EQ(waiter.Paths().size(), 1u);

    watcher.Stop();
    std::filesystem::remove_all(watch_dir);
}
