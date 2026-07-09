#include "dns_etw_monitor.hpp"

#include <QDateTime>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>

namespace avdashboard {

namespace {

// ThreatFox sometimes reports confidence_level as a JSON number, sometimes
// as a numeric string, depending on API version -- parse either.
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

DnsEtwMonitor::DnsEtwMonitor() = default;

DnsEtwMonitor::~DnsEtwMonitor() {
    StopMonitoring();
}

void DnsEtwMonitor::StartMonitoring() {
    if (monitoring_.load()) return;
    monitoring_.store(true);

    session_ = std::make_unique<avetw::DnsEtwSession>([this](const avetw::DnsQueryEvent& ev) {
        const QString domain = QString::fromStdString(ev.query_name);
        if (domain.isEmpty()) return;

        DnsQuery q;
        q.timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
        q.domain = domain;
        // The DNS-Client provider's QueryCompleted event doesn't carry a
        // parsed record type -- "A" is a display label of convenience, not
        // something actually read off this event.
        q.query_type = QString::fromUtf8("A");
        {
            const QString results = QString::fromStdString(ev.query_results);
            const int semi = results.indexOf(';');
            q.result_ip = semi >= 0 ? results.left(semi) : results;
        }

        const bool known = IsKnownC2(domain);
        q.is_c2 = known;
        const int score = known ? GetThreatScore(domain) : 0;
        q.threat_level = !known ? QString::fromUtf8("SAFE")
                        : score >= 90 ? QString::fromUtf8("CRITICAL")
                        : score >= 70 ? QString::fromUtf8("HIGH")
                                      : QString::fromUtf8("MEDIUM");

        {
            std::lock_guard<std::mutex> lock(queries_mutex_);
            queries_.insert(queries_.begin(), q); // newest first
            if (queries_.size() > 500) queries_.pop_back();
        }
        if (known && c2_detected_cb_) c2_detected_cb_(q);
    });

    monitor_thread_ = std::thread([this] {
        try {
            session_->Start(); // blocks until Stop()
        } catch (const std::exception& e) {
            monitoring_.store(false);
            if (error_cb_) error_cb_(e.what());
        }
    });
}

void DnsEtwMonitor::StopMonitoring() {
    monitoring_.store(false);
    if (session_) {
        try { session_->Stop(); } catch (const std::exception&) {}
    }
    if (monitor_thread_.joinable()) monitor_thread_.join();
    session_.reset();
}

bool DnsEtwMonitor::FetchIocFeed() {
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

    std::vector<IocEntry> fetched;
    for (const auto& entry : parsed["data"]) {
        if (entry.value("ioc_type", std::string()) != "domain") continue;
        const QString domain = QString::fromStdString(entry.value("ioc", std::string()));
        if (domain.isEmpty()) continue;

        IocEntry e;
        e.domain = domain;
        const QString threat_type = QString::fromStdString(entry.value("threat_type", std::string()));
        e.threat_type = threat_type.contains("botnet_cc", Qt::CaseInsensitive) ||
                                threat_type.contains("c2", Qt::CaseInsensitive)
                            ? QString::fromUtf8("C2")
                            : (threat_type.isEmpty() ? QString::fromUtf8("Malware") : threat_type);
        e.threat_family = QString::fromStdString(entry.value("malware_printable", std::string("Unknown")));
        e.threat_score = ParseConfidence(entry);
        fetched.push_back(std::move(e));
    }
    if (fetched.empty()) return false; // nothing usable -- don't wipe an existing database with an empty one

    std::lock_guard<std::mutex> lock(ioc_mutex_);
    ioc_database_ = std::move(fetched);
    return true;
}

std::vector<DnsQuery> DnsEtwMonitor::GetRecentQueries(int limit) {
    std::lock_guard<std::mutex> lock(queries_mutex_);
    std::vector<DnsQuery> result(queries_.begin(),
                                queries_.begin() + std::min(limit, (int)queries_.size()));
    return result;
}

bool DnsEtwMonitor::IsKnownC2(const QString& domain) {
    std::lock_guard<std::mutex> lock(ioc_mutex_);
    return std::any_of(ioc_database_.begin(), ioc_database_.end(),
                      [&domain](const IocEntry& e) {
                          return e.domain == domain || domain.contains(e.domain);
                      });
}

int DnsEtwMonitor::GetThreatScore(const QString& domain) {
    std::lock_guard<std::mutex> lock(ioc_mutex_);
    auto it = std::find_if(ioc_database_.begin(), ioc_database_.end(),
                          [&domain](const IocEntry& e) {
                              return e.domain == domain || domain.contains(e.domain);
                          });
    return (it != ioc_database_.end()) ? it->threat_score : 0;
}

} // namespace avdashboard
