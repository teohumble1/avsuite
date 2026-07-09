#pragma once

#include <functional>
#include <memory>
#include <string>

namespace avrealtimeblock {

// Returns true to ALLOW the file open, false to BLOCK it (the kernel side
// completes the create with STATUS_ACCESS_DENIED). Called synchronously on
// this class's message-pump thread, so it directly gates how long that one
// file-open stalls -- keep it fast. See driver/AvMiniFilter for the kernel
// side of this contract; that driver isn't part of this CMake build and
// must be kept in sync by hand (AVMF_NOTIFICATION / AVMF_REPLY in
// AvMiniFilter.h mirror Notification / Reply in minifilter_client.cpp).
using VerdictCallback = std::function<bool(const std::wstring& file_path)>;

// User-mode side of the AvMiniFilter communication port. Connects to
// \AvMiniFilterPort and answers every file-create notification with a
// verdict from `callback`. The driver fails *open* (allows the file) if
// this client isn't connected, replies Block as STATUS_TIMEOUT would
// suggest, or doesn't reply within its own timeout -- so a crash or slow
// verdict here degrades to detect-only, never to a system-wide hang.
//
// The driver accepts only one client connection
// (FltCreateCommunicationPort's MaxConnections=1) and this class services
// one message at a time, so every file-create on the machine serializes
// behind whatever `callback` does. A deliberate skeleton-level
// simplification -- see AvMiniFilter.c's file header for the production
// follow-up (thread pool on this side).
class MinifilterClient {
public:
    explicit MinifilterClient(VerdictCallback callback);
    ~MinifilterClient();

    MinifilterClient(const MinifilterClient&) = delete;
    MinifilterClient& operator=(const MinifilterClient&) = delete;

    // Throws std::runtime_error if \AvMiniFilterPort doesn't exist, i.e.
    // AvMiniFilter.sys isn't loaded -- expected on any machine that hasn't
    // opted into Phase 4's kernel component. Non-fatal to the caller: catch
    // it and keep running detect-only, the same way avetw's elevation
    // failure is handled.
    void Start();
    void Stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace avrealtimeblock
