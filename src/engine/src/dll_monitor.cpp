#include "dll_monitor.hpp"

namespace avengine {

DllMonitor::DllMonitor() = default;

DllMonitor::~DllMonitor() {
    Stop();
}

bool DllMonitor::Start() {
    // TODO: Register PsSetLoadImageNotifyRoutine callback in driver
    started_ = true;
    return true;
}

void DllMonitor::Stop() {
    if (started_) {
        // TODO: Unregister callback
        started_ = false;
    }
}

bool DllMonitor::IsRunning() const {
    return started_;
}

}  // namespace avengine
