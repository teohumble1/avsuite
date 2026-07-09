#include "avetw/etw_session.hpp"

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

constexpr USHORT kProcessStartOpcode = 1;

} // namespace

struct EtwSession::Impl {
    ProcessEventCallback callback;
    krabs::user_trace trace{L"AvSuiteProcessTrace"};
};

EtwSession::EtwSession(ProcessEventCallback callback) : impl_(std::make_unique<Impl>()) {
    impl_->callback = std::move(callback);
}

EtwSession::~EtwSession() {
    Stop();
}

void EtwSession::Start() {
    krabs::provider<> provider(L"Microsoft-Windows-Kernel-Process");

    provider.add_on_event_callback([this](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        if (schema.event_opcode() != kProcessStartOpcode) return;

        krabs::parser parser(schema);
        avbehavior::ProcessEvent event;
        try {
            event.process_id = parser.parse<std::uint32_t>(L"ProcessID");
            event.parent_process_id = parser.parse<std::uint32_t>(L"ParentProcessID");
            event.image_path = NarrowFromWide(parser.parse<std::wstring>(L"ImageName"));
        } catch (const std::exception&) {
            return;
        }
        // CommandLine is optional — some provider versions omit it; don't drop the event if absent.
        try {
            event.command_line = NarrowFromWide(parser.parse<std::wstring>(L"CommandLine"));
        } catch (const std::exception&) {}

        impl_->callback(event);
    });

    impl_->trace.enable(provider);
    impl_->trace.start(); // blocks until Stop()
}

void EtwSession::Stop() {
    impl_->trace.stop();
}

} // namespace avetw
