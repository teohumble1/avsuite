#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "avbehavior/process_tree.hpp"
#include "avbehavior/rule.hpp"
#include "avcore/detection_event.hpp"

namespace avbehavior {

// Owns the process tree plus the fixed set of behavioral rules, and is the
// single entry point both the live ETW consumer and unit tests drive events
// through.
class RuleEngine {
public:
    static RuleEngine WithDefaultRules();

    void AddRule(std::unique_ptr<IRule> rule);

    // Updates the process tree, then runs every rule against the new event.
    // Also performs kill-chain correlation: if a parent PID was previously
    // marked malicious (by behavior rules or by the static scanner via
    // MarkPidMalicious), an extra BEH.AV_KILL_CHAIN event is emitted.
    std::vector<avcore::DetectionEvent> OnProcessCreate(const ProcessEvent& event);

    // Called by the scan engine when a static scan (YARA/PE) triggered by an
    // ETW process-create event finds a malicious verdict.  Thread-safe.
    void MarkPidMalicious(std::uint32_t pid, const std::string& rule_id);

    const ProcessTree& Tree() const { return tree_; }

private:
    ProcessTree tree_;
    std::vector<std::unique_ptr<IRule>> rules_;

    // unique_ptr so RuleEngine remains movable (std::mutex is not movable)
    std::unique_ptr<std::mutex> flagged_mutex_{std::make_unique<std::mutex>()};
    // pid → rule_id that caused the flag; bounded to kMaxFlaggedPids entries
    std::unordered_map<std::uint32_t, std::string> flagged_pids_;
    static constexpr std::size_t kMaxFlaggedPids = 2048;
};

} // namespace avbehavior
