#pragma once

#include "avetw/dns_etw_session.hpp"

#include <QString>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>
#include <functional>

namespace avdashboard {

struct DnsQuery {
    QString timestamp;
    QString domain;
    QString query_type;   // label of convenience -- see .cpp, not actually parsed off the wire
    QString result_ip;
    QString threat_level; // "CRITICAL", "HIGH", "MEDIUM", "SAFE"
    bool is_c2 = false;
};

struct IocEntry {
    QString domain;
    QString threat_type;   // "C2", "Malware", etc. -- from ThreatFox's threat_type field
    QString threat_family; // "Emotet", "TrickBot", etc. -- from ThreatFox's malware_printable
    int threat_score = 0;  // ThreatFox confidence_level, 0-100
};

// Wraps avetw::DnsEtwSession (real ETW capture of the Microsoft-Windows-DNS-
// Client provider) and a real IOC feed from abuse.ch ThreatFox, so a live DNS
// query can be flagged against actually-fetched threat intel instead of a
// hardcoded domain list.
class DnsEtwMonitor {
public:
    DnsEtwMonitor();
    ~DnsEtwMonitor();

    void StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const { return monitoring_.load(); }

    // Real call to abuse.ch ThreatFox (POST /api/v1/, {"query":"get_iocs"}) --
    // free, no API key. Returns false on network/parse failure or an empty
    // result; ioc_database_ is left as-is in that case rather than being
    // silently replaced with nothing.
    bool FetchIocFeed();

    std::vector<DnsQuery> GetRecentQueries(int limit = 100);

    bool IsKnownC2(const QString& domain);
    int GetThreatScore(const QString& domain);

    void SetC2DetectedCallback(std::function<void(const DnsQuery&)> cb) {
        c2_detected_cb_ = std::move(cb);
    }
    // Fired if the ETW session fails to start -- most commonly, the process
    // isn't running as Administrator. Previously this failed silently.
    void SetErrorCallback(std::function<void(const std::string&)> cb) {
        error_cb_ = std::move(cb);
    }

private:
    std::atomic<bool> monitoring_{false};
    std::thread monitor_thread_;
    std::unique_ptr<avetw::DnsEtwSession> session_;

    std::vector<DnsQuery> queries_;
    std::vector<IocEntry> ioc_database_;
    std::mutex queries_mutex_;
    std::mutex ioc_mutex_;
    std::function<void(const DnsQuery&)> c2_detected_cb_;
    std::function<void(const std::string&)> error_cb_;
};

} // namespace avdashboard
