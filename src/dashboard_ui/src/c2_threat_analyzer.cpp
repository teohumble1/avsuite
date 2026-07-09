#include "c2_threat_analyzer.hpp"

#include "avpe/authenticode.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>

namespace avdashboard {

namespace {

std::string NarrowUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, out.data(), len, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

int ParseConfidence(const nlohmann::json& entry) {
    if (!entry.contains("confidence_level")) return 0;
    const auto& v = entry["confidence_level"];
    if (v.is_number()) return v.get<int>();
    if (v.is_string()) {
        try { return std::stoi(v.get<std::string>()); } catch (const std::exception&) { return 0; }
    }
    return 0;
}

} // namespace

C2ThreatAnalyzer::C2ThreatAnalyzer() {
    // Cloudflare IP ranges (common CDN masking) -- static reference data, not
    // fabricated threat intel.
    cloudflare_ips_ = {
        "1.1.1.1", "1.0.0.1", "104.16.0.0/12", "188.114.96.0/20",
        "198.41.128.0/17", "162.158.0.0/15"
    };

    zero_trust_gateways_ = {
        "gateway.zero-trust.com", "secure-dns.zero-trust.net",
        "dns.cloudflare.com", "dns.google.com"
    };

    // ioc_database_ starts empty -- caller must call FetchRealIOC() to
    // populate it. No fabricated fallback data.
}

C2ThreatAnalyzer::~C2ThreatAnalyzer() {}

bool C2ThreatAnalyzer::FetchRealIOC() {
    httplib::Client client("https://threatfox-api.abuse.ch");
    client.set_connection_timeout(10);
    client.set_read_timeout(20);

    const std::string body = R"({"query":"get_iocs","days":3})";
    auto res = client.Post("/api/v1/", body, "application/json");
    if (!res || res->status != 200) return false;

    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(res->body);
    } catch (const std::exception&) {
        return false;
    }
    if (parsed.value("query_status", std::string()) != "ok") return false;
    if (!parsed.contains("data") || !parsed["data"].is_array()) return false;

    std::vector<C2ThreatIndicator> fetched;
    for (const auto& entry : parsed["data"]) {
        const std::string ioc_type = entry.value("ioc_type", std::string());
        if (ioc_type != "domain" && ioc_type != "ip:port") continue;

        C2ThreatIndicator ind;
        const std::string ioc = entry.value("ioc", std::string());
        if (ioc.empty()) continue;
        if (ioc_type == "domain") {
            ind.domain = QString::fromStdString(ioc);
        } else {
            // "ip:port" -- keep just the IP portion.
            const auto colon = ioc.find(':');
            ind.ip_address = QString::fromStdString(colon == std::string::npos ? ioc : ioc.substr(0, colon));
        }

        ind.threat_family = QString::fromStdString(entry.value("malware_printable", std::string("Unknown")));
        ind.threat_score = ParseConfidence(entry);
        const QString threat_type = QString::fromStdString(entry.value("threat_type", std::string()));
        ind.beacon_pattern = threat_type.isEmpty() ? QString::fromUtf8("Unknown") : threat_type;
        ind.is_cloudflare = false;   // not reported by ThreatFox -- left false rather than guessed
        ind.is_zero_trust = false;
        ind.is_legitimate_process = false;
        ind.verdict = ind.threat_score >= 80 ? QString::fromUtf8("MALICIOUS")
                    : ind.threat_score >= 50 ? QString::fromUtf8("SUSPICIOUS")
                                             : QString::fromUtf8("UNKNOWN");
        fetched.push_back(std::move(ind));
    }
    if (fetched.empty()) return false; // nothing usable -- don't wipe an existing database with an empty one

    ioc_database_ = std::move(fetched);
    return true;
}

C2ThreatIndicator C2ThreatAnalyzer::AnalyzeDomain(const QString& domain) {
    auto it = std::find_if(ioc_database_.begin(), ioc_database_.end(),
                          [&domain](const C2ThreatIndicator& ioc) {
                              return !ioc.domain.isEmpty() &&
                                     (ioc.domain == domain || domain.contains(ioc.domain));
                          });

    if (it != ioc_database_.end()) {
        return *it;
    }

    C2ThreatIndicator unknown;
    unknown.domain = domain;
    unknown.threat_score = 0;
    unknown.is_legitimate_process = true;
    unknown.verdict = "UNKNOWN";
    return unknown;
}

BehaviorAnalysis C2ThreatAnalyzer::AnalyzeProcessBehavior(std::uint32_t pid, const QString& domain) {
    BehaviorAnalysis analysis;
    analysis.pid = pid;
    analysis.connecting_domains.push_back(domain);

    // Real signal: is the connecting process's on-disk image Authenticode-
    // signed? Everything else in this function is a domain-keyword
    // heuristic, not actual behavior/traffic inspection.
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (h) {
        wchar_t path_buf[MAX_PATH] = {};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, path_buf, &size)) {
            const std::wstring wpath(path_buf, size);
            analysis.process_path = QString::fromWCharArray(wpath.c_str());
            const auto slash = analysis.process_path.lastIndexOf('\\');
            analysis.process_name = slash >= 0 ? analysis.process_path.mid(slash + 1) : analysis.process_path;
            analysis.is_signed = avpe::IsAuthenticodeSigned(NarrowUtf8(wpath));
        }
        CloseHandle(h);
    }

    const bool domain_flagged = domain.contains("emotet", Qt::CaseInsensitive) ||
                                 domain.contains("trickbot", Qt::CaseInsensitive) ||
                                 domain.contains("ransomware", Qt::CaseInsensitive);
    if (domain_flagged && !analysis.is_signed) {
        analysis.verdict = "MALICIOUS";
        analysis.risk_score = 90;
    } else if (domain_flagged) {
        // Signed doesn't guarantee benign (a legit signed binary can be
        // compromised or side-loaded), but it's materially different from an
        // unsigned process hitting the same domain -- downgraded, not cleared.
        analysis.verdict = "SUSPICIOUS";
        analysis.risk_score = 60;
    } else {
        analysis.verdict = "LEGITIMATE";
        analysis.risk_score = 0;
    }

    return analysis;
}

bool C2ThreatAnalyzer::VerifyC2Threat(const QString& domain) {
    auto threat = AnalyzeDomain(domain);

    if (threat.threat_score < 80) return false;
    if (threat.is_cloudflare && !threat.is_legitimate_process) return true;
    if (threat.is_zero_trust) return false;

    return threat.threat_score >= 90;
}

bool C2ThreatAnalyzer::IsCloudflareIP(const QString& ip) {
    return ip.startsWith("104.16") || ip.startsWith("188.114") ||
           ip.startsWith("198.41") || ip.startsWith("162.158");
}

bool C2ThreatAnalyzer::IsZeroTrustGateway(const QString& ip, const QString& domain) {
    (void)ip;
    return domain.contains("zero-trust") || domain.contains("cloudflare-dns") ||
           domain.contains("dns.google") || domain.contains("dns.quad9");
}

QString C2ThreatAnalyzer::GetBeaconPattern(const QString& domain) {
    return AnalyzeDomain(domain).beacon_pattern;
}

} // namespace avdashboard
