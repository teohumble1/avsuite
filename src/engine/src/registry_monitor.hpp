#pragma once

#include <cstdint>
#include <string>

namespace avengine {

enum class RegistryOperation {
    CreateKey,
    SetValue,
    DeleteKey,
    DeleteValue,
};

struct RegistryEvent {
    uint64_t process_id;
    RegistryOperation operation;
    std::wstring registry_path;
    std::wstring value_name;
    bool is_suspicious;  // Write to Run, RunOnce, Services, AppInit_DLLs, etc.
};

class RegistryMonitor {
public:
    RegistryMonitor();
    ~RegistryMonitor();

    bool Start();
    void Stop();
    bool IsRunning() const;

private:
    bool started_ = false;
};

}  // namespace avengine
