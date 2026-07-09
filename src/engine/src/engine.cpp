#include "avengine/engine.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <combaseapi.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "avbehavior/rule_engine.hpp"
#include "avetw/etw_session.hpp"
#include "avpe/pe_analyzer.hpp"
#include "avrealtime/folder_watcher.hpp"
#include "avrealtimeblock/minifilter_client.hpp"
#include "avregscan/registry_scanner.hpp"
#include "avremediation/quarantine.hpp"
#include "avstaticscan/hash_signature.hpp"
#include "avstaticscan/yara_engine.hpp"
#include "avstorage/database.hpp"

namespace avengine {

struct ScanMetrics {
    std::string file_path;
    std::uint64_t file_size_bytes = 0;
    std::uint64_t hash_check_ms = 0;
    std::uint64_t yara_scan_ms = 0;
    std::uint64_t pe_analysis_ms = 0;
    std::uint64_t total_scan_ms = 0;
    int detections_count = 0;
};

struct Engine::Impl {
    avcore::Config config;
    DetectionCallback on_detection;

    std::unique_ptr<avstorage::Database> db;
    std::unique_ptr<avstaticscan::YaraEngine> yara;
    avbehavior::RuleEngine behavior_engine = avbehavior::RuleEngine::WithDefaultRules();

    std::unique_ptr<avrealtime::FolderWatcher> watcher;
    std::unique_ptr<avetw::EtwSession> etw_session;
    std::thread etw_thread;
    std::unique_ptr<avrealtimeblock::MinifilterClient> minifilter_client;

    std::mutex etw_raw_mutex;
    EtwRawCallback etw_raw_cb;

    // Deduplicate ETW image scans so each unique executable path is only
    // scanned once per engine lifetime, not once per process creation.
    std::mutex etw_scan_mutex;
    std::unordered_set<std::string> etw_scanned_paths;

    // Scheduled scan
    std::thread scheduled_scan_thread;
    std::atomic<bool> scheduled_scan_stop{false};

    // Cancel flag for ScanDirectory / ScanPersistence.
    std::atomic<bool> scan_cancel{false};

    // Serialises DB writes and the detection callback across worker threads.
    std::mutex emit_mutex_;
    std::condition_variable scheduled_scan_cv;
    std::mutex scheduled_scan_mutex;
    bool realtime_started = false;

    // Performance metrics tracking (ring buffer: last 1000 scans)
    mutable std::mutex metrics_mutex_;
    std::vector<ScanMetrics> recent_metrics;
    static constexpr size_t kMaxMetricsHistory = 1000;

    void Emit(const avcore::DetectionEvent& event) {
        std::lock_guard<std::mutex> lock(emit_mutex_);
        db->InsertDetection(event);
        on_detection(event);
    }

    void RecordMetrics(const ScanMetrics& metrics) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        recent_metrics.push_back(metrics);
        if (recent_metrics.size() > kMaxMetricsHistory) {
            recent_metrics.erase(recent_metrics.begin());
        }
    }

    nlohmann::json ExportMetrics() const {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        nlohmann::json metrics_array = nlohmann::json::array();
        for (const auto& m : recent_metrics) {
            metrics_array.push_back({
                {"file_path", m.file_path},
                {"file_size_bytes", m.file_size_bytes},
                {"hash_check_ms", m.hash_check_ms},
                {"yara_scan_ms", m.yara_scan_ms},
                {"pe_analysis_ms", m.pe_analysis_ms},
                {"total_scan_ms", m.total_scan_ms},
                {"detections_count", m.detections_count}
            });
        }
        return nlohmann::json{
            {"scan_count", recent_metrics.size()},
            {"metrics", metrics_array}
        };
    }

    // Quarantines `path`, attributing the action to `cause` (the first
    // Malicious-severity detection seen for this file), then emits a
    // SYS.QUARANTINED status event through the same callback so the caller
    // sees the remediation, not just the original detection. A quarantine
    // failure (file in use, already gone, etc.) is reported the same way
    // rather than thrown -- the original detection event already informed
    // the caller something is wrong even if remediation couldn't proceed.
    void Quarantine(const std::string& path, const avcore::DetectionEvent& cause) {
        const std::string hash = avstaticscan::ComputeSha256(path).value_or(std::string());
        const auto record = avremediation::Quarantine(path, hash, cause.rule_id, cause.evidence,
                                                        config.quarantine_directory, *db);

        avcore::DetectionEvent status;
        status.source = "engine";
        status.target_path = path;
        if (record) {
            status.rule_id = "SYS.QUARANTINED";
            status.severity = avcore::Severity::Info;
            status.evidence = "Moved to quarantine: " + record->quarantine_path;
        } else {
            status.rule_id = "SYS.QUARANTINE_FAILED";
            status.severity = avcore::Severity::Suspicious;
            status.evidence = "Detected as malicious but could not be quarantined (file in use or inaccessible).";
        }
        Emit(status);
    }

    // etw_pid: if non-zero, the process ID of the process that was spawned
    // (from an ETW event). After scanning, if a Malicious verdict is reached,
    // the PID is marked in the behavior engine so its children trigger
    // kill-chain correlation.
    void ScanOneFile(const std::string& path, std::uint32_t etw_pid = 0) {
        auto scan_start = std::chrono::steady_clock::now();
        std::optional<avcore::DetectionEvent> malicious_cause;
        int detection_count = 0;

        auto consider = [&](const avcore::DetectionEvent& detection) {
            Emit(detection);
            ++detection_count;
            if (!malicious_cause && detection.severity == avcore::Severity::Malicious) {
                malicious_cause = detection;
            }
        };

        ScanMetrics metrics;
        metrics.file_path = path;

        std::error_code ec;
        metrics.file_size_bytes = std::filesystem::file_size(path, ec);

        auto hash_start = std::chrono::steady_clock::now();
        if (auto hash_detection = avstaticscan::CheckHashSignature(path, *db)) {
            consider(*hash_detection);
        }
        metrics.hash_check_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - hash_start).count();

        auto yara_start = std::chrono::steady_clock::now();
        if (yara) {
            for (const auto& detection : yara->ScanFile(path)) {
                consider(detection);
            }
        }
        metrics.yara_scan_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - yara_start).count();

        auto pe_start = std::chrono::steady_clock::now();
        if (auto pe_result = avpe::AnalyzeFile(path)) {
            for (const auto& detection : avpe::ToDetectionEvents(path, *pe_result)) {
                consider(detection);
            }
        }
        metrics.pe_analysis_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - pe_start).count();

        metrics.total_scan_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - scan_start).count();
        metrics.detections_count = detection_count;
        RecordMetrics(metrics);

        if (malicious_cause) {
            if (etw_pid != 0) behavior_engine.MarkPidMalicious(etw_pid, malicious_cause->rule_id);
            Quarantine(path, *malicious_cause);
        }
    }

    static std::string ExpandEnv(const std::string& s) {
        char buf[MAX_PATH] = {};
        DWORD len = ExpandEnvironmentStringsA(s.c_str(), buf, MAX_PATH);
        return (len > 0 && len <= MAX_PATH) ? std::string(buf) : s;
    }

    static std::chrono::system_clock::time_point NextScheduledFireTime(const avcore::ScheduledScanConfig& cfg) {
        if (cfg.interval == "on_boot") {
            return std::chrono::system_clock::now() + std::chrono::seconds(30);
        }
        int hh = 2, mm = 0;
        if (cfg.time_hhmm.size() >= 5) {
            try {
                hh = std::stoi(cfg.time_hhmm.substr(0, 2));
                mm = std::stoi(cfg.time_hhmm.substr(3, 2));
            } catch (...) {}
        }
        auto now = std::chrono::system_clock::now();
        auto now_t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        localtime_s(&tm, &now_t);
        tm.tm_hour = hh;
        tm.tm_min = mm;
        tm.tm_sec = 0;
        tm.tm_isdst = -1;
        auto target = std::chrono::system_clock::from_time_t(mktime(&tm));
        const auto stride = (cfg.interval == "weekly") ? std::chrono::hours(24 * 7) : std::chrono::hours(24);
        while (target <= now) target += stride;
        return target;
    }

    void ScanDirectoryImpl(const std::string& directory) {
        std::error_code ec;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(
                 directory, std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (scheduled_scan_stop || scan_cancel) return;
            if (entry.is_regular_file()) ScanOneFile(entry.path().string());
        }
    }

    // ── Persistence scan helpers ───────────────────────────────────────────

    static bool IsTrustedPath(const std::wstring& path_lower) {
        return path_lower.find(L"c:\\windows\\") == 0
            || path_lower.find(L"c:\\program files\\") == 0
            || path_lower.find(L"c:\\program files (x86)\\") == 0;
    }

    static std::string ExtractXmlTag(const std::string& xml, const std::string& tag,
                                      std::size_t search_from = 0) {
        const std::string open  = "<" + tag + ">";
        const std::string close = "</" + tag + ">";
        const auto s = xml.find(open, search_from);
        if (s == std::string::npos) return {};
        const auto e = xml.find(close, s + open.size());
        if (e == std::string::npos) return {};
        std::string val = xml.substr(s + open.size(), e - s - open.size());
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t'
                                || val.front() == '\r' || val.front() == '\n'))
            val.erase(val.begin());
        while (!val.empty() && (val.back()  == ' ' || val.back()  == '\t'
                                || val.back()  == '\r' || val.back()  == '\n'))
            val.pop_back();
        return val;
    }

    void ScanScheduledTasksImpl() {
        const std::filesystem::path tasks_root = "C:\\Windows\\System32\\Tasks";
        std::error_code ec;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(
                 tasks_root, std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (scan_cancel) return;
            if (!entry.is_regular_file()) continue;

            std::ifstream f(entry.path(), std::ios::binary);
            if (!f) continue;
            const std::string xml((std::istreambuf_iterator<char>(f)),
                                   std::istreambuf_iterator<char>());

            // Tasks may contain multiple <Exec> actions
            std::size_t pos = 0;
            while (true) {
                std::string cmd = ExtractXmlTag(xml, "Command", pos);
                if (cmd.empty()) break;
                pos = xml.find("<Command>", pos) + 1;

                // Expand env vars
                char expanded[MAX_PATH] = {};
                ExpandEnvironmentStringsA(cmd.c_str(), expanded, sizeof(expanded));
                std::wstring wide_path = std::filesystem::path(expanded).wstring();
                std::wstring wide_lower = wide_path;
                std::transform(wide_lower.begin(), wide_lower.end(), wide_lower.begin(), ::towlower);

                if (!IsTrustedPath(wide_lower) && !cmd.empty() && cmd[0] != '<') {
                    avcore::DetectionEvent ev;
                    ev.source = "persistence";
                    ev.target_path = entry.path().string();
                    ev.rule_id = "PERSIST.SCHTASK_UNUSUAL_PATH";
                    ev.severity = avcore::Severity::Suspicious;
                    ev.evidence = "Task command outside trusted paths: " + cmd;
                    Emit(ev);
                }
                // Scan the binary regardless of location
                if (std::filesystem::exists(wide_path, ec))
                    ScanOneFile(std::filesystem::path(wide_path).string());
            }
        }
    }

    void ScanServicesImpl() {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (!scm) return;

        DWORD needed = 0, returned = 0, resume = 0;
        EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               nullptr, 0, &needed, &returned, &resume, nullptr);

        std::vector<BYTE> buf(needed + 4);
        resume = 0;
        if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                    buf.data(), static_cast<DWORD>(buf.size()),
                                    &needed, &returned, &resume, nullptr)) {
            CloseServiceHandle(scm);
            return;
        }

        auto* svcs = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < returned && !scan_cancel; ++i) {
            SC_HANDLE svc = OpenServiceW(scm, svcs[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (!svc) continue;

            DWORD cfg_needed = 0;
            QueryServiceConfigW(svc, nullptr, 0, &cfg_needed);
            std::vector<BYTE> cfg_buf(cfg_needed + 4);
            auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfg_buf.data());
            if (QueryServiceConfigW(svc, cfg, static_cast<DWORD>(cfg_buf.size()), &cfg_needed)
                && cfg->lpBinaryPathName) {
                // Strip leading quotes / arguments
                std::wstring bin(cfg->lpBinaryPathName);
                if (!bin.empty() && bin[0] == L'"') {
                    const auto close = bin.find(L'"', 1);
                    bin = (close != std::wstring::npos) ? bin.substr(1, close - 1) : bin.substr(1);
                } else {
                    const auto sp = bin.find(L' ');
                    if (sp != std::wstring::npos) bin = bin.substr(0, sp);
                }

                std::wstring bin_lower = bin;
                std::transform(bin_lower.begin(), bin_lower.end(), bin_lower.begin(), ::towlower);
                std::error_code ec;
                if (!IsTrustedPath(bin_lower) && std::filesystem::exists(bin, ec))
                    ScanOneFile(std::filesystem::path(bin).string());
            }
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }

    void ScanWmiSubscriptionsImpl() {
        // S_OK = we initialised, S_FALSE = already inited on this thread (fine),
        // RPC_E_CHANGED_MODE = inited with different model (also fine to proceed).
        const HRESULT hr_co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        const bool we_own_com = (hr_co == S_OK);

        IWbemLocator* locator = nullptr;
        if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                     IID_IWbemLocator,
                                     reinterpret_cast<void**>(&locator)))) {
            if (we_own_com) CoUninitialize();
            return;
        }

        IWbemServices* services = nullptr;
        BSTR ns = SysAllocString(L"ROOT\\subscription");
        const HRESULT hr_connect = locator->ConnectServer(
            ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
        SysFreeString(ns);
        locator->Release();

        if (FAILED(hr_connect)) { if (we_own_com) CoUninitialize(); return; }

        CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                           nullptr, RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

        static const struct { const wchar_t* wql; const char* rule; } kQueries[] = {
            { L"SELECT * FROM __EventConsumer", "PERSIST.WMI_EVENT_CONSUMER" },
            { L"SELECT * FROM __EventFilter",   "PERSIST.WMI_EVENT_FILTER"   },
        };

        for (const auto& q : kQueries) {
            if (scan_cancel) break;
            IEnumWbemClassObject* enumerator = nullptr;
            BSTR lang = SysAllocString(L"WQL");
            BSTR query = SysAllocString(q.wql);
            const HRESULT hr = services->ExecQuery(
                lang, query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &enumerator);
            SysFreeString(lang);
            SysFreeString(query);
            if (FAILED(hr)) continue;

            IWbemClassObject* obj = nullptr;
            ULONG n = 0;
            while (enumerator->Next(WBEM_INFINITE, 1, &obj, &n) == S_OK) {
                VARIANT name_var{};
                std::string consumer_name;
                if (obj->Get(L"Name", 0, &name_var, nullptr, nullptr) == S_OK
                    && name_var.vt == VT_BSTR)
                    consumer_name = std::filesystem::path(name_var.bstrVal).string();
                VariantClear(&name_var);

                avcore::DetectionEvent ev;
                ev.source = "persistence";
                ev.target_path = "WMI:ROOT\\subscription";
                ev.rule_id = q.rule;
                ev.severity = avcore::Severity::Suspicious;
                ev.evidence = "WMI subscription found: "
                              + (consumer_name.empty() ? "(unnamed)" : consumer_name);
                Emit(ev);
                obj->Release();
            }
            enumerator->Release();
        }
        services->Release();
        if (we_own_com) CoUninitialize();
    }

    void ScanPersistenceImpl(const ProgressCallback& on_progress) {
        const auto step = [&](int cur, int total, const char* label) {
            if (on_progress) on_progress(cur, total);
            avcore::DetectionEvent status;
            status.source = "persistence";
            status.target_path = label;
            status.rule_id = "SYS.PERSIST_SCAN_STEP";
            status.severity = avcore::Severity::Info;
            status.evidence = std::string("Scanning: ") + label;
            Emit(status);
        };
        step(0, 3, "Scheduled Tasks");
        if (!scan_cancel) ScanScheduledTasksImpl();
        step(1, 3, "Services");
        if (!scan_cancel) ScanServicesImpl();
        step(2, 3, "WMI Subscriptions");
        if (!scan_cancel) ScanWmiSubscriptionsImpl();
        if (on_progress) on_progress(3, 3);
    }

    void RunScheduledScan(const avcore::ScheduledScanConfig& cfg) {
        if (!cfg.target_path.empty()) {
            const std::string target = ExpandEnv(cfg.target_path);
            std::filesystem::is_directory(target) ? ScanDirectoryImpl(target) : ScanOneFile(target);
        } else {
            for (const auto& dir : config.watch_directories) {
                if (scheduled_scan_stop) return;
                ScanDirectoryImpl(ExpandEnv(dir));
            }
        }
    }

    // Stops any running scheduled thread, then starts a new one if cfg.enabled.
    // Must not be called while holding scheduled_scan_mutex.
    void RestartScheduledThread(const avcore::ScheduledScanConfig& cfg) {
        if (scheduled_scan_thread.joinable()) {
            scheduled_scan_stop = true;
            scheduled_scan_cv.notify_all();
            scheduled_scan_thread.join();
        }
        if (!cfg.enabled) return;
        scheduled_scan_stop = false;
        scheduled_scan_thread = std::thread([this, cfg] {
            while (!scheduled_scan_stop) {
                auto fire = NextScheduledFireTime(cfg);
                {
                    std::unique_lock<std::mutex> lock(scheduled_scan_mutex);
                    scheduled_scan_cv.wait_until(lock, fire,
                                                  [this] { return scheduled_scan_stop.load(); });
                }
                if (scheduled_scan_stop) break;
                RunScheduledScan(cfg);
                if (cfg.interval == "on_boot") break;
            }
        });
    }

    void StopScheduledThread() {
        scheduled_scan_stop = true;
        scheduled_scan_cv.notify_all();
        if (scheduled_scan_thread.joinable()) scheduled_scan_thread.join();
    }

    // Scans all committed, readable, private/mapped memory regions of `pid`.
    // Skips regions that are guard-protected, PAGE_NOACCESS, or >64 MB.
    // Returns total YARA detections emitted.
    int ScanProcessMemoryImpl(std::uint32_t pid) {
        // Well-known Windows system processes that are safe to skip.
        // Scanning these generates false positives from JIT, compressed DLLs,
        // and legitimate syscall usage patterns in OS components.
        static const std::unordered_set<std::string> kSkipList = {
            "system", "registry", "memory compression", "idle",
            "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "lsm.exe",
            "svchost.exe", "dwm.exe", "fontdrvhost.exe",
            "sihost.exe", "taskhostw.exe", "runtimebroker.exe",
            "ctfmon.exe", "conhost.exe", "dllhost.exe",
            "spoolsv.exe", "audiodg.exe", "dashost.exe",
            "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
            "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
            "securityhealthsystray.exe", "wuauclt.exe", "wermgr.exe",
            "msiexec.exe", "wlanext.exe", "explorer.exe",
        };

        HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!h) return 0;

        // Get a human-readable label: "pid:1234 (notepad.exe)"
        wchar_t img_name[MAX_PATH] = {};
        GetProcessImageFileNameW(h, img_name, MAX_PATH);
        const std::wstring ws(img_name);
        const std::size_t slash = ws.rfind(L'\\');
        std::string exe_name = std::filesystem::path(
            slash != std::wstring::npos ? ws.substr(slash + 1) : ws).string();

        // Lowercase for case-insensitive comparison
        std::transform(exe_name.begin(), exe_name.end(), exe_name.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        if (kSkipList.count(exe_name)) {
            CloseHandle(h);
            return 0;
        }

        const std::string pid_label = "PID:" + std::to_string(pid)
                                      + (exe_name.empty() ? "" : " (" + exe_name + ")");

        static constexpr SIZE_T kMaxRegion = 64ull * 1024 * 1024; // 64 MB
        SYSTEM_INFO si{};
        GetSystemInfo(&si);

        std::vector<std::uint8_t> buf;
        MEMORY_BASIC_INFORMATION mbi{};
        auto* addr = static_cast<const char*>(si.lpMinimumApplicationAddress);
        const auto* end  = static_cast<const char*>(si.lpMaximumApplicationAddress);

        // Only scan private executable pages — this is where injected shellcode
        // and hollowed sections live. Skipping heap/stack (READWRITE) and shared
        // mapped files eliminates the bulk of false positives from JIT engines,
        // compressed data, and shared system DLLs.
        static constexpr DWORD kExecMask =
            PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        int detections = 0;
        int region_count = 0;
        while (addr < end) {
            if (scan_cancel) break;
            if (!VirtualQueryEx(h, addr, &mbi, sizeof(mbi))) break;

            const bool scannable =
                mbi.State == MEM_COMMIT
                && mbi.RegionSize >= 4096
                && mbi.RegionSize <= kMaxRegion
                && !(mbi.Protect & PAGE_GUARD)
                && !(mbi.Protect & PAGE_NOACCESS)
                && mbi.Type == MEM_PRIVATE
                && (mbi.Protect & kExecMask);

            if (scannable && yara) {
                buf.resize(mbi.RegionSize);
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(h, mbi.BaseAddress, buf.data(), mbi.RegionSize, &bytes_read)
                    && bytes_read > 0) {
                    const std::string region_label = pid_label + "@0x"
                        + [&]{ std::ostringstream o; o << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress); return o.str(); }();
                    for (auto& det : yara->ScanBytes(buf.data(), bytes_read, region_label)) {
                        det.evidence = "[Memory] " + det.evidence;
                        Emit(det);
                        ++detections;
                    }
                }
                // Yield every 32 scanned regions so other threads stay responsive.
                if ((++region_count & 31) == 0)
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            // Guard against a zero-size region so the pointer always advances --
            // a RegionSize of 0 would otherwise spin this per-process walk forever.
            if (mbi.RegionSize == 0) break;
            addr += mbi.RegionSize;
        }
        CloseHandle(h);
        return detections;
    }

    // Verdict for AvMiniFilter.sys's blocking PreCreate hook: true allows
    // the file open, false denies it (STATUS_ACCESS_DENIED at the kernel).
    // Runs on the minifilter client's single message-pump thread and
    // directly gates how long that file-open stalls, so this stays cheap --
    // hash + YARA only, no PE/authenticode parse (ScanOneFile's slower,
    // report-only check). Only a Malicious-severity match blocks; Suspicious
    // is still recorded and surfaced via Emit, same as every other source,
    // but doesn't deny the open -- a wrong "Suspicious" verdict shouldn't be
    // able to brick a legitimate app.
    bool EvaluateForBlock(const std::wstring& wide_path) {
        const std::string path = std::filesystem::path(wide_path).string();

        bool malicious = false;
        if (auto hash_detection = avstaticscan::CheckHashSignature(path, *db)) {
            Emit(*hash_detection);
            malicious = malicious || hash_detection->severity == avcore::Severity::Malicious;
        }
        if (yara) {
            for (const auto& detection : yara->ScanFile(path)) {
                Emit(detection);
                malicious = malicious || detection.severity == avcore::Severity::Malicious;
            }
        }

        if (malicious) {
            avcore::DetectionEvent blocked;
            blocked.rule_id = "SYS.MINIFILTER_BLOCKED";
            blocked.source = "minifilter";
            blocked.severity = avcore::Severity::Malicious;
            blocked.target_path = path;
            blocked.evidence = "Kernel minifilter denied file open (STATUS_ACCESS_DENIED).";
            Emit(blocked);
        }

        return !malicious;
    }
};

Engine::Engine(avcore::Config config, DetectionCallback on_detection) : impl_(std::make_unique<Impl>()) {
    impl_->config = std::move(config);
    impl_->on_detection = std::move(on_detection);
    impl_->db = avstorage::Database::Open(impl_->config.database_path);
    impl_->yara = avstaticscan::YaraEngine::LoadRules(impl_->config.yara_rules_directory);
}

Engine::~Engine() {
    Stop();
}

void Engine::ScanFile(const std::string& path) {
    impl_->ScanOneFile(path);
}

void Engine::CancelScan() {
    impl_->scan_cancel = true;
}

void Engine::ScanDirectory(const std::string& directory, ProgressCallback on_progress) {
    impl_->scan_cancel = false;

    // Bounded producer-consumer: avoids pre-collecting millions of paths into
    // a vector (which OOMs on large drives like C:\).
    constexpr int kQueueMax = 256;
    std::queue<std::string> q;
    std::mutex q_mutex;
    std::condition_variable q_cv;
    bool producer_done = false;
    std::atomic<int> completed{0};

    if (on_progress) on_progress(0, 0); // indeterminate until first file done

    const int n_workers = static_cast<int>(std::min(4u, std::thread::hardware_concurrency()));
    std::vector<std::thread> workers;
    workers.reserve(static_cast<std::size_t>(n_workers));
    for (int t = 0; t < n_workers; ++t) {
        workers.emplace_back([&] {
            while (true) {
                std::string path;
                {
                    std::unique_lock<std::mutex> lk(q_mutex);
                    q_cv.wait(lk, [&] {
                        return !q.empty() || producer_done || impl_->scan_cancel.load();
                    });
                    if (q.empty()) break;
                    path = std::move(q.front());
                    q.pop();
                }
                q_cv.notify_all();
                if (!impl_->scan_cancel) {
                    impl_->ScanOneFile(path);
                    const int done = completed.fetch_add(1, std::memory_order_relaxed) + 1;
                    if (on_progress && (done % 50 == 0)) on_progress(done, 0);
                }
            }
        });
    }

    // Producer: iterate filesystem and feed the queue.
    std::error_code ec;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
             directory, std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (impl_->scan_cancel) break;
        if (!entry.is_regular_file(ec)) continue;
        {
            std::unique_lock<std::mutex> lk(q_mutex);
            q_cv.wait(lk, [&] {
                return static_cast<int>(q.size()) < kQueueMax || impl_->scan_cancel.load();
            });
            if (!impl_->scan_cancel) q.push(entry.path().string());
        }
        q_cv.notify_all();
    }

    {
        std::lock_guard<std::mutex> lk(q_mutex);
        producer_done = true;
    }
    q_cv.notify_all();
    for (auto& w : workers) w.join();

    const int total = completed.load();
    if (on_progress) on_progress(total, total);
}

void Engine::ScanPersistence(ProgressCallback on_progress) {
    impl_->scan_cancel = false;
    impl_->ScanPersistenceImpl(on_progress);
}

void Engine::SetEtwRawCallback(EtwRawCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->etw_raw_mutex);
    impl_->etw_raw_cb = std::move(cb);
}

std::vector<avcore::DetectionEvent> Engine::RecentDetections(int limit) {
    return impl_->db->RecentDetections(limit);
}

std::vector<avcore::QuarantineRecord> Engine::ListQuarantine() {
    return impl_->db->ListQuarantine();
}

bool Engine::RestoreFromQuarantine(std::int64_t quarantine_id) {
    return avremediation::Restore(quarantine_id, *impl_->db);
}

avstorage::DbStats Engine::GetStats() {
    return impl_->db->GetStats();
}

bool Engine::DeleteQuarantine(std::int64_t quarantine_id) {
    return avremediation::Delete(quarantine_id, *impl_->db);
}

void Engine::ClearHistory() {
    impl_->db->ClearDetections();
}

HashListTransferResult Engine::ExportHashLists(const std::string& path) {
    HashListTransferResult result;

    nlohmann::json root;
    nlohmann::json whitelist_array = nlohmann::json::array();
    for (const auto& entry : impl_->db->ListWhitelistHashes()) {
        whitelist_array.push_back({{"sha256", entry.sha256}, {"note", entry.note}});
    }
    nlohmann::json blacklist_array = nlohmann::json::array();
    for (const auto& entry : impl_->db->ListBlacklistHashes()) {
        blacklist_array.push_back({{"sha256", entry.sha256}, {"note", entry.note}});
    }
    root["whitelist_hash"] = whitelist_array;
    root["blacklist_hash"] = blacklist_array;

    std::ofstream out(path);
    if (!out) {
        result.error = "Could not open '" + path + "' for writing.";
        return result;
    }
    out << root.dump(2);

    result.success = true;
    result.whitelist_count = static_cast<int>(whitelist_array.size());
    result.blacklist_count = static_cast<int>(blacklist_array.size());
    return result;
}

HashListTransferResult Engine::ImportHashLists(const std::string& path) {
    HashListTransferResult result;

    std::ifstream in(path);
    if (!in) {
        result.error = "Could not open '" + path + "' for reading.";
        return result;
    }

    nlohmann::json root;
    try {
        in >> root;
    } catch (const std::exception& e) {
        result.error = std::string("Invalid JSON: ") + e.what();
        return result;
    }

    for (const auto& entry : root.value("whitelist_hash", nlohmann::json::array())) {
        const std::string sha256 = entry.value("sha256", std::string());
        if (sha256.empty()) continue;
        impl_->db->AddHashToWhitelist(sha256, entry.value("note", std::string()));
        ++result.whitelist_count;
    }
    for (const auto& entry : root.value("blacklist_hash", nlohmann::json::array())) {
        const std::string sha256 = entry.value("sha256", std::string());
        if (sha256.empty()) continue;
        impl_->db->AddHashToBlacklist(sha256, entry.value("note", std::string()));
        ++result.blacklist_count;
    }

    result.success = true;
    return result;
}

UpdateResult Engine::CheckForSignatureUpdates(const std::string& server_base_url) {
    UpdateResult result;

    httplib::Client client(server_base_url);
    auto manifest_response = client.Get("/manifest.json");
    if (!manifest_response || manifest_response->status != 200) {
        result.error = "Could not reach update server at " + server_base_url;
        return result;
    }

    nlohmann::json manifest;
    try {
        manifest = nlohmann::json::parse(manifest_response->body);
    } catch (const std::exception&) {
        result.error = "Update server returned an invalid manifest.";
        return result;
    }

    const std::string server_version = manifest.value("db_version", std::string());
    const std::string expected_hash = manifest.value("db_sha256", std::string());
    const std::string local_version = impl_->db->GetAppliedSignatureDbVersion();

    if (!server_version.empty() && server_version == local_version) {
        result.version = local_version;
        return result; // already up to date
    }

    auto signatures_response = client.Get("/signatures.json");
    if (!signatures_response || signatures_response->status != 200) {
        result.error = "Could not download signature update from " + server_base_url;
        return result;
    }

    const auto actual_hash = avstaticscan::ComputeSha256Bytes(signatures_response->body);
    if (!actual_hash || *actual_hash != expected_hash) {
        result.error = "Downloaded signature DB failed integrity check -- discarded.";
        return result;
    }

    nlohmann::json signatures_array;
    try {
        signatures_array = nlohmann::json::parse(signatures_response->body);
    } catch (const std::exception&) {
        result.error = "Update server returned an invalid signature list.";
        return result;
    }

    int applied = 0;
    for (const auto& entry : signatures_array) {
        avstorage::SignatureRecord record;
        record.sha256 = entry.value("sha256", std::string());
        record.malware_name = entry.value("malware_name", std::string());
        record.severity = static_cast<avcore::Severity>(entry.value("severity", 2));
        if (record.sha256.empty()) continue;
        impl_->db->UpsertSignature(record);
        ++applied;
    }
    impl_->db->SetAppliedSignatureDbVersion(server_version);

    result.updated = true;
    result.version = server_version;
    result.signature_count = applied;
    return result;
}

void Engine::ScanRegistry() {
    for (const auto& detection : avregscan::ScanAndEvaluate()) {
        impl_->Emit(detection);
    }
}

void Engine::StartRealtimeProtection() {
    impl_->watcher = std::make_unique<avrealtime::FolderWatcher>(
        impl_->config.watch_directories, [this](const std::string& path) { impl_->ScanOneFile(path); },
        impl_->config.debounce_ms);
    impl_->watcher->Start();

    impl_->etw_session = std::make_unique<avetw::EtwSession>([this](const avbehavior::ProcessEvent& event) {
        {
            std::lock_guard<std::mutex> lock(impl_->etw_raw_mutex);
            if (impl_->etw_raw_cb) impl_->etw_raw_cb(event);
        }
        for (const auto& detection : impl_->behavior_engine.OnProcessCreate(event)) {
            impl_->Emit(detection);
        }
        // Scan the process image the first time we see each unique path.
        // Runs on a detached thread so the ETW callback returns immediately.
        if (!event.image_path.empty()) {
            bool first_seen = false;
            {
                std::lock_guard<std::mutex> lock(impl_->etw_scan_mutex);
                first_seen = impl_->etw_scanned_paths.insert(event.image_path).second;
            }
            if (first_seen) {
                std::thread([this, path = event.image_path, pid = event.process_id] {
                    impl_->ScanOneFile(path, pid);
                }).detach();
            }
        }
    });

    impl_->etw_thread = std::thread([this] {
        try {
            impl_->etw_session->Start(); // blocks until Stop()
        } catch (const std::exception& e) {
            // Most common cause: process isn't elevated. Surface this as a
            // status event through the same callback rather than crashing --
            // folder-watch protection should keep running either way.
            avcore::DetectionEvent status;
            status.rule_id = "SYS.ETW_START_FAILED";
            status.source = "engine";
            status.severity = avcore::Severity::Info;
            status.evidence = std::string("Live ETW process feed could not start: ") + e.what() +
                               " (requires Administrator).";
            impl_->on_detection(status);
        }
    });

    {
        avcore::DetectionEvent ev;
        ev.rule_id = "SYS.REALTIME_STARTED";
        ev.source = "engine";
        ev.severity = avcore::Severity::Info;
        ev.evidence = "Folder watch and realtime protection started.";
        impl_->on_detection(ev);
    }

    impl_->minifilter_client = std::make_unique<avrealtimeblock::MinifilterClient>(
        [this](const std::wstring& path) { return impl_->EvaluateForBlock(path); });
    try {
        impl_->minifilter_client->Start();
        avcore::DetectionEvent ok;
        ok.rule_id = "SYS.MINIFILTER_CONNECTED";
        ok.source = "engine";
        ok.severity = avcore::Severity::Info;
        ok.evidence = "AvMiniFilter.sys connected — real-time kernel blocking active.";
        impl_->on_detection(ok);
    } catch (const std::exception& e) {
        avcore::DetectionEvent status;
        status.rule_id = "SYS.MINIFILTER_CONNECT_FAILED";
        status.source = "engine";
        status.severity = avcore::Severity::Info;
        status.evidence = std::string("Real-time blocking driver not available: ") + e.what();
        impl_->on_detection(status);
    }

    impl_->realtime_started = true;
    impl_->RestartScheduledThread(impl_->config.scheduled_scan);
}

void Engine::Stop() {
    impl_->realtime_started = false;
    impl_->StopScheduledThread();
    if (impl_->watcher) impl_->watcher->Stop();
    if (impl_->etw_session) impl_->etw_session->Stop();
    if (impl_->etw_thread.joinable()) impl_->etw_thread.join();
    if (impl_->minifilter_client) impl_->minifilter_client->Stop();
}

int Engine::ScanProcessMemory(std::uint32_t pid) {
    return impl_->ScanProcessMemoryImpl(pid);
}

int Engine::ScanAllProcesses(ProgressCallback on_progress) {
    // Drop to below-normal priority so the scan doesn't starve other processes.
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

    DWORD pids[2048] = {};
    DWORD needed = 0;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) return 0;

    const int count = static_cast<int>(needed / sizeof(DWORD));
    impl_->scan_cancel = false;
    if (on_progress) on_progress(0, count);

    const DWORD self_pid = GetCurrentProcessId();
    int total = 0;
    for (int i = 0; i < count; ++i) {
        if (impl_->scan_cancel) break;
        if (pids[i] == 0 || pids[i] == self_pid) continue;
        total += impl_->ScanProcessMemoryImpl(pids[i]);
        if (on_progress) on_progress(i + 1, count);
        // Yield 10 ms between processes so the UI and other threads stay responsive.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    return total;
}

void Engine::SetScheduledScan(const avcore::ScheduledScanConfig& cfg) {
    impl_->config.scheduled_scan = cfg;
    if (impl_->realtime_started) {
        impl_->RestartScheduledThread(cfg);
    }
}

void Engine::AddToWhitelist(const std::string& sha256, const std::string& note) {
    impl_->db->AddHashToWhitelist(sha256, note);
}

void Engine::RemoveFromWhitelist(const std::string& sha256) {
    impl_->db->RemoveHashFromWhitelist(sha256);
}

void Engine::AddToBlacklist(const std::string& sha256, const std::string& note) {
    impl_->db->AddHashToBlacklist(sha256, note);
}

void Engine::RemoveFromBlacklist(const std::string& sha256) {
    impl_->db->RemoveHashFromBlacklist(sha256);
}

std::vector<avstorage::HashListEntry> Engine::ListWhitelistHashes() {
    return impl_->db->ListWhitelistHashes();
}

std::vector<avstorage::HashListEntry> Engine::ListBlacklistHashes() {
    return impl_->db->ListBlacklistHashes();
}

std::string Engine::LookupVirusTotal(const std::string& sha256) {
    if (impl_->config.virustotal_api_key.empty()) {
        return "VirusTotal API key chưa được cấu hình. Vào Cài đặt để thêm key.";
    }
    if (sha256.empty()) {
        return "Không có SHA-256 để tra cứu.";
    }

    httplib::Client client("https://www.virustotal.com");
    client.set_connection_timeout(10);
    client.set_read_timeout(15);

    httplib::Headers headers = {
        {"x-apikey", impl_->config.virustotal_api_key},
        {"Accept", "application/json"},
    };

    const std::string endpoint = "/api/v3/files/" + sha256;
    auto res = client.Get(endpoint.c_str(), headers);

    if (!res) {
        return "Không thể kết nối tới VirusTotal (kiểm tra mạng).";
    }
    if (res->status == 404) {
        return "Hash không có trong cơ sở dữ liệu VirusTotal (file chưa được phân tích).";
    }
    if (res->status == 401) {
        return "API key không hợp lệ hoặc hết hạn.";
    }
    if (res->status == 429) {
        return "Vượt quá giới hạn request VirusTotal (free: 4 req/min).";
    }
    if (res->status != 200) {
        return "VirusTotal trả về HTTP " + std::to_string(res->status) + ".";
    }

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(res->body);
    } catch (...) {
        return "Không thể parse kết quả từ VirusTotal.";
    }

    const auto& attrs = j.value("data", nlohmann::json::object())
                         .value("attributes", nlohmann::json::object());
    const auto& stats = attrs.value("last_analysis_stats", nlohmann::json::object());

    const int malicious  = stats.value("malicious",  0);
    const int suspicious = stats.value("suspicious", 0);
    const int undetected = stats.value("undetected", 0);
    const int total      = malicious + suspicious + undetected +
                           stats.value("harmless", 0) + stats.value("failure", 0) +
                           stats.value("type-unsupported", 0);

    std::string threat_label = attrs.value("popular_threat_classification",
                                           nlohmann::json::object())
                                .value("suggested_threat_label", std::string());

    std::ostringstream out;
    out << "SHA-256: " << sha256 << "\n";
    out << "Phát hiện: " << malicious << "/" << total << " engine(s)";
    if (suspicious > 0) out << "  (" << suspicious << " nghi ngờ)";
    out << "\n";
    if (!threat_label.empty()) {
        out << "Nhãn đe dọa: " << threat_label << "\n";
    }

    const std::string name = attrs.value("meaningful_name", std::string());
    if (!name.empty()) out << "Tên file: " << name << "\n";

    // List the first few detections
    const auto& results = attrs.value("last_analysis_results", nlohmann::json::object());
    int shown = 0;
    for (auto it = results.begin(); it != results.end() && shown < 6; ++it) {
        const std::string cat = it.value().value("category", std::string());
        if (cat == "malicious" || cat == "suspicious") {
            out << "  • " << it.key() << ": "
                << it.value().value("result", std::string("(unknown)")) << "\n";
            ++shown;
        }
    }
    if (malicious + suspicious > shown) {
        out << "  ... và " << (malicious + suspicious - shown) << " engine(s) khác.\n";
    }

    return out.str();
}

namespace {

// Shared GET + error-mapping for the VT IP/domain lookups (VT's file lookup
// above predates this and is left as-is to avoid touching working code).
struct VtLookupOutcome {
    bool ok = false;
    std::string error;   // set when !ok
    nlohmann::json attrs; // data.attributes, when ok
};

VtLookupOutcome VtGet(const avcore::Config& config, const std::string& endpoint) {
    VtLookupOutcome out;
    if (config.virustotal_api_key.empty()) {
        out.error = "VirusTotal API key chưa được cấu hình. Vào Cài đặt để thêm key.";
        return out;
    }
    httplib::Client client("https://www.virustotal.com");
    client.set_connection_timeout(10);
    client.set_read_timeout(15);
    httplib::Headers headers = {
        {"x-apikey", config.virustotal_api_key},
        {"Accept", "application/json"},
    };
    auto res = client.Get(endpoint.c_str(), headers);
    if (!res) {
        out.error = "Không thể kết nối tới VirusTotal (kiểm tra mạng).";
        return out;
    }
    if (res->status == 404) {
        out.error = "Không có dữ liệu trong VirusTotal cho mục tiêu này.";
        return out;
    }
    if (res->status == 401) {
        out.error = "API key không hợp lệ hoặc hết hạn.";
        return out;
    }
    if (res->status == 429) {
        out.error = "Vượt quá giới hạn request VirusTotal (free: 4 req/min).";
        return out;
    }
    if (res->status != 200) {
        out.error = "VirusTotal trả về HTTP " + std::to_string(res->status) + ".";
        return out;
    }
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(res->body);
    } catch (...) {
        out.error = "Không thể parse kết quả từ VirusTotal.";
        return out;
    }
    out.attrs = j.value("data", nlohmann::json::object()).value("attributes", nlohmann::json::object());
    out.ok = true;
    return out;
}

std::string FormatVtStats(const nlohmann::json& attrs) {
    const auto& stats = attrs.value("last_analysis_stats", nlohmann::json::object());
    const int malicious  = stats.value("malicious",  0);
    const int suspicious = stats.value("suspicious", 0);
    const int total = malicious + suspicious + stats.value("undetected", 0) +
                       stats.value("harmless", 0) + stats.value("timeout", 0);
    std::ostringstream out;
    out << "Phát hiện: " << malicious << "/" << total << " engine(s)";
    if (suspicious > 0) out << "  (" << suspicious << " nghi ngờ)";
    out << "\n";
    return out.str();
}

} // namespace

std::string Engine::LookupVirusTotalIp(const std::string& ip) {
    if (ip.empty()) return "Không có IP để tra cứu.";
    const auto outcome = VtGet(impl_->config, "/api/v3/ip_addresses/" + ip);
    if (!outcome.ok) return outcome.error;
    const auto& a = outcome.attrs;
    std::ostringstream out;
    out << "IP: " << ip << "\n";
    out << FormatVtStats(a);
    const std::string owner = a.value("as_owner", std::string());
    if (!owner.empty()) out << "AS owner: " << owner << "\n";
    const std::string country = a.value("country", std::string());
    if (!country.empty()) out << "Quốc gia: " << country << "\n";
    out << "Reputation: " << a.value("reputation", 0) << "\n";
    return out.str();
}

std::string Engine::LookupVirusTotalDomain(const std::string& domain) {
    if (domain.empty()) return "Không có domain để tra cứu.";
    const auto outcome = VtGet(impl_->config, "/api/v3/domains/" + domain);
    if (!outcome.ok) return outcome.error;
    const auto& a = outcome.attrs;
    std::ostringstream out;
    out << "Domain: " << domain << "\n";
    out << FormatVtStats(a);
    const std::string registrar = a.value("registrar", std::string());
    if (!registrar.empty()) out << "Registrar: " << registrar << "\n";
    out << "Reputation: " << a.value("reputation", 0) << "\n";
    const auto& categories = a.value("categories", nlohmann::json::object());
    if (!categories.empty()) {
        out << "Categories: ";
        bool first = true;
        for (auto it = categories.begin(); it != categories.end(); ++it) {
            if (!first) out << ", ";
            out << it.value().get<std::string>();
            first = false;
        }
        out << "\n";
    }
    return out.str();
}

namespace {

// Splits one CSV line honoring double-quoted fields (which may contain
// commas, e.g. ssdeep hashes). Quotes themselves are stripped.
std::vector<std::string> ParseCsvLine(const std::string& line) {
    std::vector<std::string> fields;
    std::string cur;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '"') {
            in_quotes = !in_quotes;
        } else if (c == ',' && !in_quotes) {
            fields.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    fields.push_back(cur);
    return fields;
}

} // namespace

ThreatIntelFetchResult Engine::FetchMalwareBazaarRecent() {
    ThreatIntelFetchResult result;

    httplib::Client client("https://bazaar.abuse.ch");
    client.set_connection_timeout(10);
    client.set_read_timeout(20);
    client.set_follow_location(true);

    httplib::Headers headers = { {"Accept", "text/csv"} };
    if (!impl_->config.malwarebazaar_api_key.empty()) {
        headers.emplace("Auth-Key", impl_->config.malwarebazaar_api_key);
    }

    auto res = client.Get("/export/csv/recent/", headers);
    if (!res) {
        result.error = "Không thể kết nối tới abuse.ch MalwareBazaar (kiểm tra mạng).";
        return result;
    }
    if (res->status == 401 || res->status == 403) {
        result.error = "abuse.ch yêu cầu Auth-Key hợp lệ. Lấy key miễn phí tại bazaar.abuse.ch (Account -> API Key) rồi nhập ở Cài đặt.";
        return result;
    }
    if (res->status != 200) {
        result.error = "MalwareBazaar trả về HTTP " + std::to_string(res->status) + ".";
        return result;
    }

    // Header line: first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,
    //   file_name,file_type_guess,mime_type,signature,clamav,vtpercent,
    //   imphash,ssdeep,tlsh
    // Comment/meta lines are prefixed with '#'.
    std::istringstream body(res->body);
    std::string line;
    while (std::getline(body, line)) {
        if (line.empty() || line[0] == '#') continue;
        const auto fields = ParseCsvLine(line);
        if (fields.size() < 9) continue;
        ThreatIntelEntry entry;
        entry.first_seen = fields[0];
        entry.sha256      = fields[1];
        entry.signature   = fields[8].empty() ? "(unknown family)" : fields[8];
        if (entry.sha256.size() != 64) continue; // skip malformed rows
        result.entries.push_back(std::move(entry));
    }

    result.success = true;
    return result;
}

std::string Engine::ExportPerformanceMetrics() {
    return impl_->ExportMetrics().dump(2);
}

} // namespace avengine
