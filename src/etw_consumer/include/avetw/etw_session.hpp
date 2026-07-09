#pragma once

#include <functional>
#include <memory>

#include "avbehavior/process_event.hpp"

namespace avetw {

using ProcessEventCallback = std::function<void(const avbehavior::ProcessEvent&)>;

// Live ETW consumer for the Microsoft-Windows-Kernel-Process provider's
// ProcessStart event (event opcode 1).
//
// Known Phase 1 limitation, verified against the published manifest: this
// provider's ProcessStartArgs template carries ProcessID, ParentProcessID,
// SessionID, and ImageName -- but NOT CommandLine. ProcessEvent::command_line
// is left empty on this live path (avbehavior::rules::RuleLolbinSuspiciousArgs
// is exercised by unit tests via synthetic events with a command line set,
// but won't see one from this feed yet). Resolving command lines for other
// processes needs either the classic NT Kernel Logger "Process" MOF provider
// or PEB inspection of the new process -- not implemented in this cut.
//
// Starting a real-time ETW session requires the caller to be an
// Administrator (or in "Performance Log Users"); Start() will throw if not.
//
// VM-only: per the project plan, only run this against live traffic inside a
// disposable, snapshotted VM -- never on a developer's primary host.
class EtwSession {
public:
    explicit EtwSession(ProcessEventCallback callback);
    ~EtwSession();

    EtwSession(const EtwSession&) = delete;
    EtwSession& operator=(const EtwSession&) = delete;

    // Blocks the calling thread until Stop() is called from elsewhere -- run
    // this on a dedicated thread.
    void Start();
    void Stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace avetw
