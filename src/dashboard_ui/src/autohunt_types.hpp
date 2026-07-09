#pragma once
#include <cstdint>
#include <string>

namespace avdashboard {

struct HuntTarget {
    std::string source;       // "DLL Intel" | "Sys Watch" | "Network"
    std::string name;
    std::string path;
    int         risk_score = 0;
    std::string description;
    std::string ai_verdict;
    bool        analyzed = false;
    int64_t     detected_epoch_s = 0;
};

void AutoHuntEnqueue(HuntTarget t);

} // namespace avdashboard
