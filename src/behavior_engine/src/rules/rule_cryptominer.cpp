#include "rules/rule_cryptominer.hpp"

#include <array>

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {
namespace {

bool Contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

// Each of these, seen once in a command line, is on its own a strong tell of a
// miner: the Stratum wire URI and XMRig's own documented CLI flags. Legitimate
// software has no reason to embed them.
constexpr std::array<const char*, 6> kHardIndicators = {
    "stratum+tcp://",
    "stratum+ssl://",
    "--donate-level",
    "--cpu-max-threads-hint",
    "--randomx",
    "--coin ",
};

// Weaker single hints -- meaningful in combination but too generic to convict
// on their own.
constexpr std::array<const char*, 4> kSoftFlags = {
    "--rig-id",
    "--nicehash",
    "--algo=rx",
    "randomx",
};

// Basenames (lower-case, no extension) of widely-abused miner binaries.
constexpr std::array<const char*, 16> kMinerBinaries = {
    "xmrig", "smrig", "xmr-stak", "xmrstak", "cpuminer", "cpuminer-multi",
    "ccminer", "nbminer", "phoenixminer", "lolminer", "t-rex", "trex",
    "nanominer", "srbminer-multi", "teamredminer", "minerd",
};

// Fragments of well-known mining-pool hostnames.
constexpr std::array<const char*, 9> kPoolDomains = {
    "minexmr", "supportxmr", "moneroocean", "nanopool.org", "hashvault",
    "monerohash", "2miners.com", "xmrpool", "pool.hashvault",
};

} // namespace

std::optional<avcore::DetectionEvent> RuleCryptominer::Evaluate(const ProcessEvent& event,
                                                                 const ProcessTree& tree) const {
    (void)tree;
    const std::string cmd = avcore::ToLowerAscii(event.command_line);
    const std::string image = avcore::ToLowerAscii(avcore::Basename(event.image_path));

    bool hard = false;
    for (const char* ind : kHardIndicators) {
        if (Contains(cmd, ind)) { hard = true; break; }
    }

    // Miner binary basename match (with or without a trailing .exe).
    bool miner_bin = false;
    for (const char* name : kMinerBinaries) {
        if (image == name || image == std::string(name) + ".exe") { miner_bin = true; break; }
    }

    bool pool_hit = false;
    for (const char* dom : kPoolDomains) {
        if (Contains(cmd, dom)) { pool_hit = true; break; }
    }

    bool soft_flag = false;
    for (const char* f : kSoftFlags) {
        if (Contains(cmd, f)) { soft_flag = true; break; }
    }

    const int soft_score = (miner_bin ? 1 : 0) + (pool_hit ? 1 : 0) + (soft_flag ? 1 : 0);
    if (!hard && soft_score == 0) {
        return std::nullopt;
    }

    avcore::DetectionEvent detection;
    detection.rule_id = Id();
    detection.source = "behavior_engine";
    detection.target_path = event.image_path;
    detection.process_id = event.process_id;
    detection.parent_process_id = event.parent_process_id;

    // A hard indicator, or two independent soft hints, is a confident miner;
    // a lone soft hint is only Suspicious.
    if (hard || soft_score >= 2) {
        detection.severity = avcore::Severity::Malicious;
        detection.evidence = "Cryptominer launch fingerprint: Stratum/XMRig indicators in the "
                             "command line or a known miner binary connecting to a mining pool ("
                             + event.image_path + ").";
    } else {
        detection.severity = avcore::Severity::Suspicious;
        detection.evidence = "Possible cryptominer indicator (single weak hint: miner-like binary "
                             "name, mining-pool domain, or mining flag) for " + event.image_path + ".";
    }
    return detection;
}

} // namespace avbehavior::rules
