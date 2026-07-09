#pragma once

#include <QString>
#include <vector>
#include <cstdint>

namespace avdashboard {

struct C2ThreatIndicator {
    QString domain;
    QString ip_address;
    QString threat_family;    // Emotet, TrickBot, Ryuk, etc. -- from ThreatFox's malware_printable
    int threat_score = 0;     // 0-100, from ThreatFox's confidence_level
    bool is_cloudflare = false;
    bool is_zero_trust = false;
    QString beacon_pattern;    // "C2" / "Malware" / etc. -- from ThreatFox's threat_type, repurposed as a label
    bool is_legitimate_process = false;
    QString verdict;          // "MALICIOUS", "SUSPICIOUS", "UNKNOWN"
};

struct BehaviorAnalysis {
    QString process_name;
    QString process_path;
    std::uint32_t pid = 0;
    bool is_signed = false;      // real: avpe::IsAuthenticodeSigned on the process's on-disk image
    bool is_microsoft = false;   // no real signer-identity check performed -- always false, not guessed
    std::vector<QString> connecting_domains;
    QString verdict;   // "LEGITIMATE", "SUSPICIOUS", "MALICIOUS"
    int risk_score = 0; // 0-100
};

// Domain/IOC reputation lookups over a real abuse.ch ThreatFox feed. This
// used to hold a hardcoded list of "real" IOCs and several methods that
// fabricated plausible-looking data (fake geo-IP, fake SSL cert checks) --
// both removed. What's left either looks up the (now real) IOC database or
// is an explicitly-labeled shallow heuristic.
class C2ThreatAnalyzer {
public:
    C2ThreatAnalyzer();
    ~C2ThreatAnalyzer();

    // Real call to abuse.ch ThreatFox (POST /api/v1/, {"query":"get_iocs"}) --
    // free, no API key. Returns false on network/parse failure or an empty
    // result; ioc_database_ is left as-is in that case.
    bool FetchRealIOC();

    // Look up domain in the IOC database. Returns an UNKNOWN indicator (not a
    // guess) if the domain isn't in it.
    C2ThreatIndicator AnalyzeDomain(const QString& domain);

    // Shallow heuristic: flags process behavior by keyword-matching the
    // domain name, plus one real signal (whether the connecting process's
    // on-disk image is Authenticode-signed, via avpe::IsAuthenticodeSigned --
    // the same check main_window_kernelbios.cpp uses for drivers). This is
    // NOT real traffic/behavior analysis -- no timing, volume, or process-tree
    // correlation happens.
    BehaviorAnalysis AnalyzeProcessBehavior(std::uint32_t pid, const QString& domain);

    // Multi-factor check over the (real) IOC database + Cloudflare/Zero
    // Trust heuristics below.
    bool VerifyC2Threat(const QString& domain);

    bool IsCloudflareIP(const QString& ip);
    bool IsZeroTrustGateway(const QString& ip, const QString& domain);

    QString GetBeaconPattern(const QString& domain);

private:
    std::vector<C2ThreatIndicator> ioc_database_;
    std::vector<QString> cloudflare_ips_;
    std::vector<QString> zero_trust_gateways_;
};

} // namespace avdashboard
