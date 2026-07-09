#include "avetw/dns_etw_session.hpp"

#include <krabs.hpp>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace avetw {

namespace {

std::string NarrowFromWide(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    const int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr,
                                          nullptr);
    if (size <= 0) return std::string();
    std::string narrow(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), narrow.data(), size, nullptr, nullptr);
    return narrow;
}

constexpr int kDnsQueryCompletedEventId = 3006;

} // namespace

struct DnsEtwSession::Impl {
    DnsQueryCallback callback;
    krabs::user_trace trace{L"AvSuiteDnsTrace"};
};

DnsEtwSession::DnsEtwSession(DnsQueryCallback callback) : impl_(std::make_unique<Impl>()) {
    impl_->callback = std::move(callback);
}

DnsEtwSession::~DnsEtwSession() {
    Stop();
}

void DnsEtwSession::Start() {
    krabs::provider<> provider(L"Microsoft-Windows-DNS-Client");

    provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        if (schema.event_id() != kDnsQueryCompletedEventId) return;

        krabs::parser parser(schema);
        DnsQueryEvent event;
        try {
            event.query_name = NarrowFromWide(parser.parse<std::wstring>(L"QueryName"));
        } catch (const std::exception&) {
            return; // no domain name -- nothing usable in this event
        }
        // QueryResults/QueryStatus are treated as optional: some provider
        // versions or query outcomes (e.g. NXDOMAIN) may omit or zero them
        // without invalidating the query name itself.
        try {
            event.query_results = NarrowFromWide(parser.parse<std::wstring>(L"QueryResults"));
        } catch (const std::exception&) {}
        try {
            event.query_status = parser.parse<std::uint32_t>(L"QueryStatus");
        } catch (const std::exception&) {}

        impl_->callback(event);
    });

    impl_->trace.enable(provider);
    impl_->trace.start(); // blocks until Stop()
}

void DnsEtwSession::Stop() {
    impl_->trace.stop();
}

} // namespace avetw
