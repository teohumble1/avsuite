#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "avcore/detection_event.hpp"

namespace avstaticscan {

// Wraps classic libyara. This is the only file in the codebase that touches
// <yara.h> -- swapping to YARA-X later only means rewriting this file.
class YaraEngine {
public:
    // Compiles every *.yar file found directly inside `rules_directory`.
    // Returns nullptr if the directory has no loadable rules.
    static std::unique_ptr<YaraEngine> LoadRules(const std::string& rules_directory);
    ~YaraEngine();

    YaraEngine(const YaraEngine&) = delete;
    YaraEngine& operator=(const YaraEngine&) = delete;

    std::vector<avcore::DetectionEvent> ScanFile(const std::string& path) const;

    // Scans an in-memory buffer instead of a file -- used by tests for
    // content (like the EICAR test string) that real-time antivirus on the
    // build machine would otherwise intercept/quarantine if written to disk.
    std::vector<avcore::DetectionEvent> ScanBytes(const std::uint8_t* data, std::size_t size,
                                                    const std::string& label) const;

private:
    explicit YaraEngine(void* compiled_rules);
    void* rules_; // YR_RULES*, kept opaque so <yara.h> doesn't leak into this public header
};

} // namespace avstaticscan
