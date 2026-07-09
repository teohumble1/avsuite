#include "avcore/config.hpp"

#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

namespace avcore {

Config Config::LoadFromFile(const std::string& path) {
    Config cfg;
    cfg.config_file_path = path;
    if (!std::filesystem::exists(path)) {
        return cfg;
    }

    std::ifstream in(path);
    nlohmann::json j;
    try {
        in >> j;
    } catch (const std::exception&) {
        return cfg;
    }

    if (j.contains("watch_directories")) {
        cfg.watch_directories = j.at("watch_directories").get<std::vector<std::string>>();
    }
    if (j.contains("database_path")) {
        cfg.database_path = j.at("database_path").get<std::string>();
    }
    if (j.contains("log_path")) {
        cfg.log_path = j.at("log_path").get<std::string>();
    }
    if (j.contains("yara_rules_directory")) {
        cfg.yara_rules_directory = j.at("yara_rules_directory").get<std::string>();
    }
    if (j.contains("quarantine_directory")) {
        cfg.quarantine_directory = j.at("quarantine_directory").get<std::string>();
    }
    if (j.contains("debounce_ms")) {
        cfg.debounce_ms = j.at("debounce_ms").get<int>();
    }
    if (j.contains("scheduled_scan")) {
        const auto& s = j.at("scheduled_scan");
        cfg.scheduled_scan.enabled = s.value("enabled", false);
        cfg.scheduled_scan.interval = s.value("interval", std::string("daily"));
        cfg.scheduled_scan.time_hhmm = s.value("time_hhmm", std::string("02:00"));
        cfg.scheduled_scan.target_path = s.value("target_path", std::string());
    }
    if (j.contains("virustotal_api_key")) {
        cfg.virustotal_api_key = j.at("virustotal_api_key").get<std::string>();
    }
    if (j.contains("malwarebazaar_api_key")) {
        cfg.malwarebazaar_api_key = j.at("malwarebazaar_api_key").get<std::string>();
    }
    if (j.contains("ai_model_path")) {
        cfg.ai_model_path = j.at("ai_model_path").get<std::string>();
    }
    if (j.contains("update_server_url")) {
        cfg.update_server_url = j.at("update_server_url").get<std::string>();
    }
    return cfg;
}

bool Config::SaveToFile(const std::string& path) const {
    nlohmann::json j;
    j["watch_directories"] = watch_directories;
    j["database_path"] = database_path;
    j["log_path"] = log_path;
    j["yara_rules_directory"] = yara_rules_directory;
    j["quarantine_directory"] = quarantine_directory;
    j["debounce_ms"] = debounce_ms;
    j["scheduled_scan"] = {
        {"enabled", scheduled_scan.enabled},
        {"interval", scheduled_scan.interval},
        {"time_hhmm", scheduled_scan.time_hhmm},
        {"target_path", scheduled_scan.target_path},
    };
    j["virustotal_api_key"] = virustotal_api_key;
    j["malwarebazaar_api_key"] = malwarebazaar_api_key;
    j["ai_model_path"] = ai_model_path;
    j["update_server_url"] = update_server_url;

    std::ofstream out(path);
    if (!out) return false;
    out << j.dump(2);
    return true;
}

} // namespace avcore
