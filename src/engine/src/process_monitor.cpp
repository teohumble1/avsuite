#include "process_monitor.hpp"

namespace avengine {

ProcessMonitor::ProcessMonitor() = default;

ProcessMonitor::~ProcessMonitor() {
    Stop();
}

bool ProcessMonitor::Start() {
    // TODO: Register PsSetCreateProcessNotifyRoutineEx callback in driver
    // For now, stub implementation
    started_ = true;
    return true;
}

void ProcessMonitor::Stop() {
    if (started_) {
        // TODO: Unregister callback
        started_ = false;
    }
}

bool ProcessMonitor::IsRunning() const {
    return started_;
}

}  // namespace avengine
