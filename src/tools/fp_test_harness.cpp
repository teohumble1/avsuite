// AvSuite False-Positive Test Harness
// Scans legitimate Windows binaries to measure FP rate per rule
// Compile: cl /std:c++17 /EHsc fp_test_harness.cpp /link <avsuite libs>
// Usage: fp_test_harness.exe <output_json>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <chrono>

// Placeholder for AvSuite engine integration
// In real build, link against libavengine.lib

struct FPTestResult {
    std::string binary_path;
    std::string binary_name;
    std::string sha256;
    std::vector<std::string> detected_rules;
    int detection_count = 0;
    bool is_legit = true;
    std::string category;  // system32, programfiles, user_tools, etc.
    std::uint64_t file_size_bytes = 0;
    std::uint64_t scan_time_ms = 0;
};

struct FPTestConfig {
    std::vector<std::string> scan_paths = {
        "C:\\Windows\\System32",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
    };
    std::vector<std::string> binary_extensions = {".exe", ".dll", ".sys"};
    int max_files = 500;  // Limit corpus size for reasonable runtime
    bool skip_known_safe = true;
};

class LegitBinaryWhitelist {
public:
    bool IsKnownSafe(const std::string& path, const std::string& filename) {
        static const std::vector<std::string> known_safe_exes = {
            "notepad.exe", "calc.exe", "mspaint.exe", "explorer.exe",
            "cmd.exe", "powershell.exe", "wmic.exe", "certutil.exe",
            "msbuild.exe", "regsvcs.exe", "regasm.exe", "installutil.exe",
            "7z.exe", "winrar.exe", "7zFM.exe"
        };

        std::string lower_filename = filename;
        std::transform(lower_filename.begin(), lower_filename.end(),
                      lower_filename.begin(), ::tolower);

        for (const auto& safe : known_safe_exes) {
            if (lower_filename == safe) return true;
        }
        return false;
    }
};

class FPTestHarness {
private:
    FPTestConfig config_;
    std::vector<FPTestResult> results_;
    LegitBinaryWhitelist whitelist_;

    std::string GetBinaryCategory(const std::string& path) {
        std::string lower_path = path;
        std::transform(lower_path.begin(), lower_path.end(),
                      lower_path.begin(), ::tolower);

        if (lower_path.find("\\system32\\") != std::string::npos) {
            return "system32";
        } else if (lower_path.find("\\program files\\") != std::string::npos) {
            return "programfiles";
        } else if (lower_path.find("\\program files (x86)\\") != std::string::npos) {
            return "programfiles_x86";
        }
        return "other";
    }

public:
    FPTestHarness(const FPTestConfig& config) : config_(config) {}

    void Scan() {
        int scanned = 0;
        for (const auto& base_path : config_.scan_paths) {
            if (scanned >= config_.max_files) break;

            std::cout << "Scanning: " << base_path << "\n";
            try {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(
                         base_path, std::filesystem::directory_options::skip_permission_denied)) {
                    if (scanned >= config_.max_files) break;

                    if (!entry.is_regular_file()) continue;

                    std::string ext = entry.path().extension().string();
                    std::string lower_ext = ext;
                    std::transform(lower_ext.begin(), lower_ext.end(),
                                  lower_ext.begin(), ::tolower);

                    bool is_binary = false;
                    for (const auto& bin_ext : config_.binary_extensions) {
                        if (lower_ext == bin_ext) {
                            is_binary = true;
                            break;
                        }
                    }
                    if (!is_binary) continue;

                    std::string filename = entry.path().filename().string();
                    if (config_.skip_known_safe && whitelist_.IsKnownSafe(entry.path().string(), filename)) {
                        continue;
                    }

                    FPTestResult result;
                    result.binary_path = entry.path().string();
                    result.binary_name = filename;
                    result.category = GetBinaryCategory(entry.path().string());
                    result.is_legit = true;
                    result.file_size_bytes = entry.file_size();

                    // TODO: Call AvSuite::Engine::ScanFile and capture detections
                    // For now, this is a placeholder

                    results_.push_back(result);
                    ++scanned;

                    if (scanned % 50 == 0) {
                        std::cout << "  Scanned " << scanned << " binaries...\n";
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Error scanning " << base_path << ": " << e.what() << "\n";
            }
        }
        std::cout << "Total scanned: " << scanned << " binaries\n";
    }

    nlohmann::json GenerateReport() {
        std::map<std::string, int> fp_by_rule;
        std::map<std::string, int> fp_by_category;
        int total_fps = 0;

        for (const auto& result : results_) {
            if (result.detection_count > 0) {
                total_fps += result.detection_count;
                for (const auto& rule : result.detected_rules) {
                    fp_by_rule[rule]++;
                }
                fp_by_category[result.category]++;
            }
        }

        nlohmann::json report;
        report["test_date"] = nlohmann::json::value_t::string;
        report["binaries_scanned"] = results_.size();
        report["total_false_positives"] = total_fps;
        report["fp_rate_percent"] = (total_fps * 100.0) / std::max(1UL, results_.size());
        report["fp_by_rule"] = fp_by_rule;
        report["fp_by_category"] = fp_by_category;

        nlohmann::json detailed_results = nlohmann::json::array();
        for (const auto& r : results_) {
            if (r.detection_count > 0) {
                detailed_results.push_back({
                    {"binary_path", r.binary_path},
                    {"binary_name", r.binary_name},
                    {"category", r.category},
                    {"file_size_bytes", r.file_size_bytes},
                    {"detection_count", r.detection_count},
                    {"detected_rules", r.detected_rules},
                    {"scan_time_ms", r.scan_time_ms}
                });
            }
        }
        report["false_positives_details"] = detailed_results;

        return report;
    }

    void SaveReport(const std::string& output_path) {
        auto report = GenerateReport();
        std::ofstream out(output_path);
        out << report.dump(2);
        std::cout << "Report saved to: " << output_path << "\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: fp_test_harness.exe <output_json>\n";
        return 1;
    }

    FPTestConfig config;
    FPTestHarness harness(config);

    std::cout << "AvSuite False-Positive Test Harness\n";
    std::cout << "====================================\n\n";

    harness.Scan();
    harness.SaveReport(argv[1]);

    std::cout << "\nTest complete. Review results for high-FP rules.\n";
    return 0;
}
