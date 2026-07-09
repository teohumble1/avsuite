#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace avetw {

struct DnsQueryEvent {
    std::string query_name;     // domain queried
    std::string query_results;  // semicolon-separated result list (IPs/CNAMEs); empty on failure
    std::uint32_t query_status = 0; // 0 = success, non-zero = Win32 DNS error code
};

using DnsQueryCallback = std::function<void(const DnsQueryEvent&)>;

// Live ETW consumer for the Microsoft-Windows-DNS-Client provider's
// "DNS query completed" event (event ID 3006).
//
// Known limitation: the DNS-Client manifest doesn't carry a parsed record
// type in this event (that's inferred client-side from the query flags in
// real tooling, which isn't done here) -- callers get name/results/status
// only. Some provider versions may also omit QueryResults on a successful
// query with no answers; that's surfaced as an empty string, not an error.
//
// Starting a real-time ETW session requires the caller to be an
// Administrator (or in "Performance Log Users"); Start() will throw if not
// -- same constraint as EtwSession's process feed.
class DnsEtwSession {
public:
    explicit DnsEtwSession(DnsQueryCallback callback);
    ~DnsEtwSession();

    DnsEtwSession(const DnsEtwSession&) = delete;
    DnsEtwSession& operator=(const DnsEtwSession&) = delete;

    // Blocks the calling thread until Stop() is called from elsewhere -- run
    // this on a dedicated thread.
    void Start();
    void Stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace avetw
