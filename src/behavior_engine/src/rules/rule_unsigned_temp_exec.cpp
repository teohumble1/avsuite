#include "rules/rule_unsigned_temp_exec.hpp"

#include <mutex>
#include <unordered_map>

#include "avcore/path_utils.hpp"
#include "avpe/authenticode.hpp"

namespace avbehavior::rules {

namespace {

// Cache Authenticode results per image path: IsAuthenticodeSigned performs
// disk I/O + WinVerifyTrust on every call, which is expensive at high
// process-creation rates. A path is stable once the binary is on disk, so
// caching is safe. Bounded at 4096 entries so the AV itself doesn't OOM.
constexpr std::size_t kCacheMax = 4096;
std::mutex g_auth_cache_mutex;
std::unordered_map<std::string, bool> g_auth_cache;

bool IsCachedSigned(const std::string& path) {
    {
        std::lock_guard<std::mutex> lk(g_auth_cache_mutex);
        const auto it = g_auth_cache.find(path);
        if (it != g_auth_cache.end()) return it->second;
    }
    const bool result = avpe::IsAuthenticodeSigned(path);
    {
        std::lock_guard<std::mutex> lk(g_auth_cache_mutex);
        if (g_auth_cache.size() < kCacheMax) g_auth_cache.emplace(path, result);
    }
    return result;
}

} // namespace

std::optional<avcore::DetectionEvent> RuleUnsignedTempExec::Evaluate(const ProcessEvent& event,
                                                                       const ProcessTree& /*tree*/) const {
    if (!avcore::IsUnderUserWritableDir(event.image_path)) {
        return std::nullopt;
    }
    if (IsCachedSigned(event.image_path)) {
        return std::nullopt;
    }

    avcore::DetectionEvent detection;
    detection.rule_id = Id();
    detection.source = "behavior_engine";
    detection.severity = avcore::Severity::Suspicious;
    detection.target_path = event.image_path;
    detection.process_id = event.process_id;
    detection.parent_process_id = event.parent_process_id;
    detection.evidence = "Process image has no valid Authenticode signature and runs from a "
                          "user-writable drop location.";
    return detection;
}

} // namespace avbehavior::rules
