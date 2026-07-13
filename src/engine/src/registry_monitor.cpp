#include "registry_monitor.hpp"

namespace avengine {

RegistryMonitor::RegistryMonitor() = default;

RegistryMonitor::~RegistryMonitor() {
    Stop();
}

bool RegistryMonitor::Start() {
    // TODO: Register CmRegisterCallbackEx in driver
    // Track persistence locations: HKLM\Software\Microsoft\Windows\CurrentVersion\Run,
    // HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce, Services registry, etc.
    started_ = true;
    return true;
}

void RegistryMonitor::Stop() {
    if (started_) {
        // TODO: Unregister callback
        started_ = false;
    }
}

bool RegistryMonitor::IsRunning() const {
    return started_;
}

}  // namespace avengine
