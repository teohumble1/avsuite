#include "avrealtimeblock/minifilter_client.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fltUser.h>

#include <atomic>
#include <stdexcept>

namespace avrealtimeblock {

namespace {

constexpr wchar_t kPortName[] = L"\\AvMiniFilterPort";

// Mirrors AVMF_MESSAGE_TYPE / AVMF_NOTIFICATION / AVMF_VERDICT / AVMF_REPLY
// in driver/AvMiniFilter/AvMiniFilter.h byte-for-byte. That header can't be
// included here (it pulls in fltKernel.h, kernel-only), so this is a
// hand-maintained mirror -- if one side's layout changes, update both.
enum class MessageType : ULONG { FileCreate = 1 };
enum class Verdict : ULONG { Allow = 0, Block = 1 };

struct Notification {
    MessageType message_type;
    wchar_t file_path[260];
};

struct Reply {
    Verdict verdict;
};

struct MessageBuffer {
    FILTER_MESSAGE_HEADER header;
    Notification notification;
};

struct ReplyBuffer {
    FILTER_REPLY_HEADER header;
    Reply payload;
};

// Minifilter normalized paths use NT device form: \Device\HarddiskVolume3\path.
// Win32 APIs (CreateFile, fopen) can't open these directly -- map back to
// a drive-letter path (C:\path) by querying DOS device names.
std::wstring DevicePathToWin32(const std::wstring& path) {
    if (path.size() < 2 || path[0] != L'\\') return path; // already Win32-style

    wchar_t drives[512] = {};
    if (!GetLogicalDriveStringsW(static_cast<DWORD>(ARRAYSIZE(drives) - 1), drives)) return path;

    for (const wchar_t* drv = drives; *drv; drv += wcslen(drv) + 1) {
        wchar_t letter[3] = { drv[0], drv[1], L'\0' }; // e.g. "C:"
        wchar_t target[MAX_PATH] = {};
        if (!QueryDosDeviceW(letter, target, MAX_PATH)) continue;

        const size_t target_len = wcslen(target);
        if (path.size() > target_len &&
            path.compare(0, target_len, target) == 0 &&
            path[target_len] == L'\\') {
            return std::wstring(letter) + path.substr(target_len);
        }
    }
    return path; // no mapping found -- return as-is (YARA will fail open → allow)
}

} // namespace

struct MinifilterClient::Impl {
    VerdictCallback callback;
    HANDLE port = INVALID_HANDLE_VALUE;
    HANDLE pump_thread = nullptr;
    HANDLE wake_event = nullptr;
    std::atomic<bool> stop_requested{false};

    static DWORD WINAPI PumpThreadProc(LPVOID param) {
        static_cast<Impl*>(param)->Pump();
        return 0;
    }

    void Pump() {
        OVERLAPPED overlapped{};
        overlapped.hEvent = wake_event;

        while (!stop_requested.load()) {
            MessageBuffer message{};
            ResetEvent(wake_event);

            const HRESULT get_hr = FilterGetMessage(port, &message.header, sizeof(message), &overlapped);
            if (get_hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                if (WaitForSingleObject(wake_event, INFINITE) != WAIT_OBJECT_0) break;
                DWORD bytes = 0;
                if (!GetOverlappedResult(port, &overlapped, &bytes, FALSE)) break;
            } else if (FAILED(get_hr)) {
                break; // port closed: driver unloaded, or our own Stop()
            }

            if (stop_requested.load()) break;

            const bool allow = callback(DevicePathToWin32(std::wstring(message.notification.file_path)));

            ReplyBuffer reply{};
            reply.header.MessageId = message.header.MessageId;
            reply.payload.verdict = allow ? Verdict::Allow : Verdict::Block;
            FilterReplyMessage(port, reinterpret_cast<PFILTER_REPLY_HEADER>(&reply), sizeof(reply));
        }
    }
};

MinifilterClient::MinifilterClient(VerdictCallback callback) : impl_(std::make_unique<Impl>()) {
    impl_->callback = std::move(callback);
}

MinifilterClient::~MinifilterClient() {
    Stop();
}

void MinifilterClient::Start() {
    const HRESULT hr = FilterConnectCommunicationPort(kPortName, 0, nullptr, 0, nullptr, &impl_->port);
    if (FAILED(hr)) {
        throw std::runtime_error(
            "Could not connect to the AvMiniFilter communication port -- "
            "is AvMiniFilter.sys loaded?");
    }

    impl_->wake_event = CreateEventW(nullptr, /*bManualReset=*/TRUE, FALSE, nullptr);
    impl_->pump_thread = CreateThread(nullptr, 0, &Impl::PumpThreadProc, impl_.get(), 0, nullptr);
}

void MinifilterClient::Stop() {
    impl_->stop_requested = true;
    if (impl_->port != INVALID_HANDLE_VALUE) {
        CloseHandle(impl_->port); // unblocks a pending FilterGetMessage
        impl_->port = INVALID_HANDLE_VALUE;
    }
    if (impl_->wake_event) {
        SetEvent(impl_->wake_event);
    }
    if (impl_->pump_thread) {
        // 5 s timeout: the pump holds the driver's scan budget (kSendTimeout100ns
        // = 5 s). Give it at least that long to return before we abandon the thread.
        WaitForSingleObject(impl_->pump_thread, 6000);
        CloseHandle(impl_->pump_thread);
        impl_->pump_thread = nullptr;
    }
    if (impl_->wake_event) {
        CloseHandle(impl_->wake_event);
        impl_->wake_event = nullptr;
    }
}

} // namespace avrealtimeblock
