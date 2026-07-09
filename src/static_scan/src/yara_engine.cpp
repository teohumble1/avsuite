#include "avstaticscan/yara_engine.hpp"

#include <yara.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <mutex>

namespace avstaticscan {

namespace {

std::once_flag g_yara_init_flag;

void EnsureYaraInitialized() {
    std::call_once(g_yara_init_flag, []() { yr_initialize(); });
}

// Rules declare meta: severity = "malicious" | "suspicious" | "info" (see
// src/static_scan/rules/*.yar). Defaults to Suspicious for a rule that
// matched but omitted the meta -- "it matched something" is at least worth a
// look, but shouldn't reach Engine's Malicious-only auto-quarantine without
// an explicit author opt-in.
avcore::Severity SeverityFromRule(YR_RULE* rule) {
    YR_META* meta;
    yr_rule_metas_foreach(rule, meta) {
        if (meta->type == META_TYPE_STRING && std::strcmp(meta->identifier, "severity") == 0) {
            if (std::strcmp(meta->string, "malicious") == 0) return avcore::Severity::Malicious;
            if (std::strcmp(meta->string, "info") == 0) return avcore::Severity::Info;
            return avcore::Severity::Suspicious;
        }
    }
    return avcore::Severity::Suspicious;
}

struct ScanContext {
    std::vector<avcore::DetectionEvent>* detections;
    const std::string* path;
};

int ScanCallback(YR_SCAN_CONTEXT* /*context*/, int message, void* message_data, void* user_data) {
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;

    auto* rule = reinterpret_cast<YR_RULE*>(message_data);
    auto* ctx = reinterpret_cast<ScanContext*>(user_data);

    avcore::DetectionEvent detection;
    detection.rule_id = std::string("YARA.") + rule->identifier;
    detection.source = "yara";
    detection.severity = SeverityFromRule(rule);
    detection.target_path = *ctx->path;
    detection.evidence = std::string("YARA rule '") + rule->identifier + "' matched.";
    ctx->detections->push_back(std::move(detection));

    return CALLBACK_CONTINUE;
}

} // namespace

YaraEngine::YaraEngine(void* compiled_rules) : rules_(compiled_rules) {}

YaraEngine::~YaraEngine() {
    if (rules_) yr_rules_destroy(reinterpret_cast<YR_RULES*>(rules_));
}

std::unique_ptr<YaraEngine> YaraEngine::LoadRules(const std::string& rules_directory) {
    EnsureYaraInitialized();

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return nullptr;

    bool any_rule_added = false;
    std::error_code dir_error;
    for (const auto& entry : std::filesystem::directory_iterator(rules_directory, dir_error)) {
        if (entry.path().extension() != ".yar") continue;

        FILE* file = nullptr;
        if (_wfopen_s(&file, entry.path().c_str(), L"r") != 0 || file == nullptr) continue;

        const std::string rule_namespace = entry.path().stem().string();
        const int result = yr_compiler_add_file(compiler, file, rule_namespace.c_str(), entry.path().string().c_str());
        std::fclose(file);
        if (result == 0) any_rule_added = true;
    }

    if (!any_rule_added) {
        yr_compiler_destroy(compiler);
        return nullptr;
    }

    YR_RULES* rules = nullptr;
    const int rc = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    if (rc != ERROR_SUCCESS || rules == nullptr) return nullptr;

    return std::unique_ptr<YaraEngine>(new YaraEngine(rules));
}

std::vector<avcore::DetectionEvent> YaraEngine::ScanFile(const std::string& path) const {
    std::vector<avcore::DetectionEvent> detections;
    if (!rules_) return detections;

    ScanContext ctx{&detections, &path};
    yr_rules_scan_file(reinterpret_cast<YR_RULES*>(rules_), path.c_str(), 0, ScanCallback, &ctx,
                        /*timeout_seconds=*/10);
    return detections;
}

std::vector<avcore::DetectionEvent> YaraEngine::ScanBytes(const std::uint8_t* data, std::size_t size,
                                                            const std::string& label) const {
    std::vector<avcore::DetectionEvent> detections;
    if (!rules_) return detections;

    ScanContext ctx{&detections, &label};
    yr_rules_scan_mem(reinterpret_cast<YR_RULES*>(rules_), data, size, 0, ScanCallback, &ctx,
                       /*timeout_seconds=*/10);
    return detections;
}

} // namespace avstaticscan
