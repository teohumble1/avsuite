#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include "avbehavior/rule.hpp"
#include "avbehavior/process_event.hpp"
#include "avcore/detection_event.hpp"
#include "avcore/path_utils.hpp"

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

// Shared command-line pattern table used by the MITRE-mapped behavior rules.
// Each entry pairs an (optional) image basename with an (optional) lowercase
// command-line substring and the severity to raise. Keeping this in one place
// lets each rule stay a thin, declarative table instead of re-implementing the
// same lowercase/basename/substring matching loop.
struct CommandPattern {
    const char* binary;        // lowercase image basename; "" matches any binary
    const char* arg_substring; // lowercase substring; "" matches on the binary alone
    const char* description;   // human-readable evidence
    avcore::Severity severity; // Malicious = rarely legitimate; Suspicious = dual-use
};

// Returns a DetectionEvent for the first matching pattern, or nullopt. A pattern
// matches when its (non-empty) binary equals the image basename AND its
// (non-empty) arg_substring is present in the lowercased command line. Patterns
// should be ordered most-specific first.
inline std::optional<avcore::DetectionEvent> MatchCommandPatterns(
        const std::string& rule_id,
        const CommandPattern* patterns,
        std::size_t count,
        const ProcessEvent& event) {
    const std::string image_name = avcore::ToLowerAscii(avcore::Basename(event.image_path));
    const std::string cmd_lower  = avcore::ToLowerAscii(event.command_line);

    for (std::size_t i = 0; i < count; ++i) {
        const CommandPattern& p = patterns[i];
        if (p.binary[0] != '\0' && image_name != p.binary) continue;
        if (p.arg_substring[0] != '\0' && cmd_lower.find(p.arg_substring) == std::string::npos) continue;

        avcore::DetectionEvent d;
        d.rule_id           = rule_id;
        d.source            = "behavior_engine";
        d.severity          = p.severity;
        d.target_path       = event.image_path;
        d.process_id        = event.process_id;
        d.parent_process_id = event.parent_process_id;
        d.evidence          = std::string(p.description) + ". Command line: " + event.command_line;
        return d;
    }
    return std::nullopt;
}

template <std::size_t N>
std::optional<avcore::DetectionEvent> MatchCommandPatterns(const std::string& rule_id,
                                                            const CommandPattern (&patterns)[N],
                                                            const ProcessEvent& event) {
    return MatchCommandPatterns(rule_id, patterns, N, event);
}

}  // namespace avbehavior
