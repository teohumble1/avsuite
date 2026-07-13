#include "avbehavior/rule_engine.hpp"

#include <string>

// Original rules
#include "rules/rule_av_killer_child.hpp"
#include "rules/rule_lolbin_susp_args.hpp"
#include "rules/rule_suspicious_parent_child.hpp"
#include "rules/rule_temp_appdata_spawn.hpp"
#include "rules/rule_unsigned_temp_exec.hpp"
// Extended detection coverage
#include "rules/rule_powershell_obfuscation.hpp"
#include "rules/rule_shadow_copy_delete.hpp"
#include "rules/rule_credential_access.hpp"
#include "rules/rule_lateral_movement.hpp"
#include "rules/rule_persistence_registry.hpp"
#include "rules/rule_wmi_execution.hpp"
#include "rules/rule_scheduled_task_abuse.hpp"
#include "rules/rule_service_installation.hpp"
#include "rules/rule_amsi_etw_bypass.hpp"
#include "rules/rule_ransomware_indicator.hpp"
#include "rules/rule_defense_evasion.hpp"
#include "rules/rule_malware_behaviors.hpp"
#include "rules/rule_cryptominer.hpp"

namespace avbehavior {

RuleEngine RuleEngine::WithDefaultRules() {
    RuleEngine engine;
    // Original 5 rules
    engine.AddRule(std::make_unique<rules::RuleTempAppDataSpawn>());
    engine.AddRule(std::make_unique<rules::RuleSuspiciousParentChild>());
    engine.AddRule(std::make_unique<rules::RuleUnsignedTempExec>());
    engine.AddRule(std::make_unique<rules::RuleLolbinSuspiciousArgs>());
    engine.AddRule(std::make_unique<rules::RuleAvKillerChild>());
    // Extended rules (x100 coverage)
    engine.AddRule(std::make_unique<rules::RulePowerShellObfuscation>());
    engine.AddRule(std::make_unique<rules::RuleShadowCopyDelete>());
    engine.AddRule(std::make_unique<rules::RuleCredentialAccess>());
    engine.AddRule(std::make_unique<rules::RuleLateralMovement>());
    engine.AddRule(std::make_unique<rules::RulePersistenceRegistry>());
    engine.AddRule(std::make_unique<rules::RuleWmiExecution>());
    engine.AddRule(std::make_unique<rules::RuleScheduledTaskAbuse>());
    engine.AddRule(std::make_unique<rules::RuleServiceInstallation>());
    engine.AddRule(std::make_unique<rules::RuleAmsiEtwBypass>());
    engine.AddRule(std::make_unique<rules::RuleRansomwareIndicator>());
    engine.AddRule(std::make_unique<rules::RuleDefenseEvasion>());
    // Malware behavior patterns (ransomware/lateral-movement/credential/obfuscation)
    engine.AddRule(std::make_unique<rules::RuleRansomwareFileOps>());
    engine.AddRule(std::make_unique<rules::RuleLateralMovementIndicators>());
    engine.AddRule(std::make_unique<rules::RuleCredentialTheftPatterns>());
    engine.AddRule(std::make_unique<rules::RuleCommandObfuscation>());
    // Cryptominer launch fingerprint (Stratum/XMRig/pool indicators)
    engine.AddRule(std::make_unique<rules::RuleCryptominer>());
    return engine;
}

void RuleEngine::AddRule(std::unique_ptr<IRule> rule) {
    rules_.push_back(std::move(rule));
}

void RuleEngine::MarkPidMalicious(std::uint32_t pid, const std::string& rule_id) {
    std::lock_guard<std::mutex> lock(*flagged_mutex_);
    if (flagged_pids_.size() >= kMaxFlaggedPids) return; // don't grow unbounded
    flagged_pids_.emplace(pid, rule_id);
}

std::vector<avcore::DetectionEvent> RuleEngine::OnProcessCreate(const ProcessEvent& event) {
    tree_.OnProcessCreate(event);

    // Snapshot under lock so rule evaluation runs lock-free
    std::unordered_map<std::uint32_t, std::string> flagged_snapshot;
    {
        std::lock_guard<std::mutex> lock(*flagged_mutex_);
        flagged_snapshot = flagged_pids_;
    }

    std::vector<avcore::DetectionEvent> detections;
    for (const auto& rule : rules_) {
        if (auto detection = rule->Evaluate(event, tree_)) {
            detections.push_back(std::move(*detection));
        }
    }

    // Kill-chain: any rule fired AND parent was already flagged malicious →
    // emit an additional high-confidence event linking the two
    auto parent_it = flagged_snapshot.find(event.parent_process_id);
    if (parent_it != flagged_snapshot.end() && !detections.empty()) {
        avcore::DetectionEvent chain;
        chain.rule_id           = "BEH.AV_KILL_CHAIN";
        chain.source            = "behavior_engine";
        chain.severity          = avcore::Severity::Malicious;
        chain.target_path       = event.image_path;
        chain.process_id        = event.process_id;
        chain.parent_process_id = event.parent_process_id;
        chain.evidence          = "Child of previously-flagged malicious process (PID "
                                  + std::to_string(event.parent_process_id)
                                  + ", rule=" + parent_it->second
                                  + "): " + detections.front().evidence;
        detections.push_back(std::move(chain));
    }

    // Propagate: if any detection from this run is Malicious, mark this PID
    // so its children can be correlated too
    for (const auto& d : detections) {
        if (d.severity == avcore::Severity::Malicious) {
            MarkPidMalicious(event.process_id, d.rule_id);
            break;
        }
    }

    return detections;
}

} // namespace avbehavior
