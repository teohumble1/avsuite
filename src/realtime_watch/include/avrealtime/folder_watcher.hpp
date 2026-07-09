#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace avrealtime {

using FileChangeCallback = std::function<void(const std::string& full_path)>;

// Watches a fixed set of directories (non-recursive subtree watch via
// ReadDirectoryChangesW with bWatchSubtree=TRUE) for create/modify events.
// Directory entries may contain environment-variable templates (e.g.
// "%TEMP%") which are expanded at Start() time; entries that don't exist on
// this machine are skipped rather than treated as an error.
//
// Repeated events for the same path within `debounce_ms` of the last fired
// callback are suppressed (leading-edge: the first event in a burst fires
// immediately, since a security scanner wants to react as soon as possible,
// not after the burst settles).
class FolderWatcher {
public:
    FolderWatcher(std::vector<std::string> directories, FileChangeCallback callback, int debounce_ms = 750);
    ~FolderWatcher();

    FolderWatcher(const FolderWatcher&) = delete;
    FolderWatcher& operator=(const FolderWatcher&) = delete;

    void Start();
    void Stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    // dir_handle is a HANDLE, passed as void* so this header doesn't need to
    // include <windows.h>.
    static void WatchDirectoryThread(Impl* impl, std::string directory, void* dir_handle);
};

} // namespace avrealtime
