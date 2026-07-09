#include "avrealtime/folder_watcher.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace avrealtime {

namespace {

std::string ExpandEnvPath(const std::string& templated) {
    char buffer[MAX_PATH] = {};
    const DWORD len = ExpandEnvironmentStringsA(templated.c_str(), buffer, MAX_PATH);
    if (len == 0 || len > MAX_PATH) return std::string();
    return std::string(buffer);
}

} // namespace

struct FolderWatcher::Impl {
    std::vector<std::string> directories;
    FileChangeCallback callback;
    int debounce_ms;

    std::atomic<bool> running{false};
    std::vector<HANDLE> handles;
    std::vector<std::thread> threads;

    std::mutex debounce_mutex;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_fired;

    void HandleChange(const std::string& full_path) {
        {
            std::lock_guard<std::mutex> lock(debounce_mutex);
            const auto now = std::chrono::steady_clock::now();
            const auto it = last_fired.find(full_path);
            if (it != last_fired.end()) {
                const auto elapsed_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second).count();
                if (elapsed_ms < debounce_ms) return;
            }
            last_fired[full_path] = now;
        }
        callback(full_path);
    }
};

void FolderWatcher::WatchDirectoryThread(Impl* impl, std::string directory, void* dir_handle_raw) {
    const HANDLE dir_handle = static_cast<HANDLE>(dir_handle_raw);
    std::vector<BYTE> buffer(64 * 1024);

    while (impl->running.load()) {
        DWORD bytes_returned = 0;
        const BOOL ok = ReadDirectoryChangesW(
            dir_handle, buffer.data(), static_cast<DWORD>(buffer.size()), /*bWatchSubtree=*/TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE, &bytes_returned,
            nullptr, nullptr);
        if (!ok) break; // handle closed or CancelIoEx'd by Stop()
        if (bytes_returned == 0) continue;

        size_t offset = 0;
        while (offset < bytes_returned) {
            const auto* notify = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buffer.data() + offset);
            const std::wstring filename(notify->FileName, notify->FileNameLength / sizeof(WCHAR));

            if (notify->Action == FILE_ACTION_ADDED || notify->Action == FILE_ACTION_MODIFIED) {
                const std::filesystem::path full_path = std::filesystem::path(directory) / filename;
                impl->HandleChange(full_path.string());
            }

            if (notify->NextEntryOffset == 0) break;
            offset += notify->NextEntryOffset;
        }
    }
}

FolderWatcher::FolderWatcher(std::vector<std::string> directories, FileChangeCallback callback, int debounce_ms)
    : impl_(std::make_unique<Impl>()) {
    impl_->directories = std::move(directories);
    impl_->callback = std::move(callback);
    impl_->debounce_ms = debounce_ms;
}

FolderWatcher::~FolderWatcher() {
    Stop();
}

void FolderWatcher::Start() {
    impl_->running = true;

    for (const auto& raw_dir : impl_->directories) {
        const std::string expanded = ExpandEnvPath(raw_dir);
        if (expanded.empty() || !std::filesystem::exists(expanded)) continue;

        const HANDLE dir_handle =
            CreateFileA(expanded.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (dir_handle == INVALID_HANDLE_VALUE) continue;

        impl_->handles.push_back(dir_handle);
        impl_->threads.emplace_back(&FolderWatcher::WatchDirectoryThread, impl_.get(), expanded,
                                     static_cast<void*>(dir_handle));
    }
}

void FolderWatcher::Stop() {
    impl_->running = false;
    for (HANDLE h : impl_->handles) {
        CancelIoEx(h, nullptr);
    }
    for (auto& t : impl_->threads) {
        if (t.joinable()) t.join();
    }
    for (HANDLE h : impl_->handles) {
        CloseHandle(h);
    }
    impl_->handles.clear();
    impl_->threads.clear();
}

} // namespace avrealtime
