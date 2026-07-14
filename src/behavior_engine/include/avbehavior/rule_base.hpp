#pragma once

#include <string>
#include <optional>
#include "avbehavior/rule.hpp"
#include "avbehavior/process_event.hpp"
#include "avcore/detection_event.hpp"

namespace avbehavior {

class RuleBase : public IRule {
public:
    virtual std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                             const ProcessTree& tree) const = 0;

protected:
    avcore::DetectionEvent MakeDetection(const std::string& rule_id,
                                         avcore::Severity severity,
                                         const std::string& evidence) const {
        avcore::DetectionEvent d;
        d.rule_id = rule_id;
        d.severity = severity;
        d.evidence = evidence;
        d.source = "behavior_engine";
        return d;
    }
};

}  // namespace avbehavior
