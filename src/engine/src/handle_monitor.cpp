#include "handle_monitor.hpp"

namespace avengine {

HandleMonitor::HandleMonitor() = default;

HandleMonitor::~HandleMonitor() {
    Stop();
}

bool HandleMonitor::Start() {
    // TODO: Register ObRegisterCallbacks in driver
    // Block PROCESS_VM_READ/PROCESS_QUERY_INFORMATION opens to lsass.exe
    started_ = true;
    return true;
}

void HandleMonitor::Stop() {
    if (started_) {
        // TODO: Unregister callback
        started_ = false;
    }
}

bool HandleMonitor::IsRunning() const {
    return started_;
}

}  // namespace avengine
