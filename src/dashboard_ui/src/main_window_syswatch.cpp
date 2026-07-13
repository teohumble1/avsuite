// main_window_syswatch.cpp — System32 / Explorer Auto-Hunt Watcher
// Watches critical system directories for unauthorized changes.
// On detection: hashes the file, checks signature, attributes to process (via ETW/PID),
// auto-collects forensic info, optionally isolates (quarantine) the file.

#include "main_window.hpp"
#include "av_quit_guard.hpp"
#include "hunt_toolbar.hpp"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QColor>
#include <QDateTime>
#include <QFont>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPainter>
#include <QPushButton>
#include <QScrollArea>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <WinTrust.h>
#include <SoftPub.h>
#include <wincrypt.h>
#include <Shlwapi.h>
#include <ShlObj.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#include <atomic>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <array>
#include <algorithm>
#include <memory>

#include "autohunt_types.hpp"

namespace avdashboard {

// ─── File event record ────────────────────────────────────────────────────────
struct SysWatchEvent {
    enum Action { Created, Modified, Deleted, Renamed };
    Action      action;
    std::string path;
    std::string filename;
    std::string sha256;
    bool        is_signed = false;
    bool        is_system_file = false;
    int64_t     size_bytes = 0;
    std::string owning_process;  // best-effort: process that may have written this
    uint32_t    owning_pid = 0;
    int         risk_score = 0;
    std::string risk_reason;
    FILETIME    timestamp;
    bool        quarantined = false;
};

// ─── SHA-256 via CryptoAPI ─────────────────────────────────────────────────────
static std::string Sha256File(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return "(unreadable)";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result = "(error)";

    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            constexpr DWORD kBufSize = 65536;
            auto buf = std::make_unique<BYTE[]>(kBufSize);
            DWORD read = 0;
            bool ok = true;
            while (ReadFile(hFile, buf.get(), kBufSize, &read, nullptr) && read > 0) {
                if (!CryptHashData(hHash, buf.get(), read, 0)) { ok = false; break; }
            }
            if (ok) {
                BYTE hash[32] = {};
                DWORD hashLen = 32;
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                    char hex[65] = {};
                    for (int i = 0; i < 32; ++i)
                        snprintf(hex + i*2, 3, "%02x", hash[i]);
                    result = hex;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
    return result;
}

// ─── Digital signature check ──────────────────────────────────────────────────
static bool IsFileSigned(const std::wstring& path) {
    WINTRUST_FILE_INFO fi = {};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();
    WINTRUST_DATA wd = {};
    wd.cbStruct            = sizeof(wd);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fi;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG res = WinVerifyTrust(nullptr, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);
    return res == ERROR_SUCCESS;
}

// ─── Heuristic risk assessment ────────────────────────────────────────────────
static int AssessRisk(const SysWatchEvent& ev, std::string& out_reason) {
    int score = 0;
    std::string reasons;

    // High-value directories
    const std::string& p = ev.path;
    const bool in_sys32 = p.find("\\System32\\") != std::string::npos ||
                          p.find("\\system32\\") != std::string::npos;
    const bool in_win   = p.find("C:\\Windows\\") != std::string::npos ||
                          p.find("c:\\windows\\") != std::string::npos;

    if (in_sys32) { score += 40; reasons += "In System32; "; }
    else if (in_win) { score += 20; reasons += "In Windows dir; "; }

    // New file created
    if (ev.action == SysWatchEvent::Created) { score += 15; reasons += "New file; "; }

    // Unsigned executable
    const std::string& fn = ev.filename;
    const bool is_exec = fn.size() > 4 &&
        (_stricmp(fn.c_str() + fn.size() - 4, ".exe") == 0 ||
         _stricmp(fn.c_str() + fn.size() - 4, ".dll") == 0 ||
         _stricmp(fn.c_str() + fn.size() - 4, ".sys") == 0 ||
         _stricmp(fn.c_str() + fn.size() - 4, ".drv") == 0);

    if (is_exec && !ev.is_signed) { score += 35; reasons += "Unsigned binary; "; }

    // DLL/SYS in System32 is especially suspicious if unsigned
    if (in_sys32 && is_exec && !ev.is_signed) { score += 20; reasons += "Unsigned sys binary; "; }

    out_reason = reasons.empty() ? "Normal activity" : reasons;
    if (!reasons.empty()) out_reason.pop_back(); // remove trailing space
    if (out_reason.back() == ';') out_reason.pop_back();

    return qMin(score, 100);
}

// ─── Directory watcher thread ─────────────────────────────────────────────────
// Uses ReadDirectoryChangesW for efficient kernel-level change notifications.
static void WatchThread(const std::wstring& dir_path,
                        std::atomic<bool>& stop_flag,
                        std::function<void(SysWatchEvent)> on_event) {
    HANDLE hDir = CreateFileW(
        dir_path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr);

    if (hDir == INVALID_HANDLE_VALUE) return;

    constexpr int kBufSize = 65536;
    auto buf = std::make_unique<BYTE[]>(kBufSize);

    OVERLAPPED ov = {};
    HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvent) { CloseHandle(hDir); return; }
    ov.hEvent = hEvent;

    while (!stop_flag.load()) {
        ResetEvent(hEvent);
        DWORD bytes_returned = 0;
        BOOL ok = ReadDirectoryChangesW(
            hDir, buf.get(), kBufSize, TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_SECURITY | FILE_NOTIFY_CHANGE_CREATION,
            &bytes_returned, &ov, nullptr);

        if (!ok && GetLastError() != ERROR_IO_PENDING) break;

        const DWORD wait = WaitForSingleObjectEx(hEvent, 1000, FALSE);
        if (stop_flag.load()) break;
        if (wait == WAIT_TIMEOUT) continue;
        if (wait != WAIT_OBJECT_0) break;

        if (!GetOverlappedResult(hDir, &ov, &bytes_returned, FALSE)) break;
        if (bytes_returned == 0) continue;

        const BYTE* ptr = buf.get();
        while (true) {
            const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(ptr);

            // Build full path
            const int name_len = info->FileNameLength / sizeof(WCHAR);
            std::wstring filename(info->FileName, name_len);
            std::wstring full_path = dir_path + L"\\" + filename;

            SysWatchEvent ev;
            GetSystemTimeAsFileTime(&ev.timestamp);

            switch (info->Action) {
            case FILE_ACTION_ADDED:           ev.action = SysWatchEvent::Created;  break;
            case FILE_ACTION_MODIFIED:        ev.action = SysWatchEvent::Modified; break;
            case FILE_ACTION_REMOVED:         ev.action = SysWatchEvent::Deleted;  break;
            case FILE_ACTION_RENAMED_NEW_NAME:ev.action = SysWatchEvent::Renamed;  break;
            default:                          ev.action = SysWatchEvent::Modified; break;
            }

            // Convert to UTF-8
            char buf8[MAX_PATH * 4] = {};
            WideCharToMultiByte(CP_UTF8, 0, full_path.c_str(), -1, buf8, MAX_PATH*4, nullptr, nullptr);
            ev.path = buf8;
            char fn8[MAX_PATH * 2] = {};
            WideCharToMultiByte(CP_UTF8, 0, filename.c_str(), -1, fn8, MAX_PATH*2, nullptr, nullptr);
            ev.filename = fn8;

            // File metadata (only if file still exists)
            if (ev.action != SysWatchEvent::Deleted) {
                WIN32_FILE_ATTRIBUTE_DATA fa = {};
                if (GetFileAttributesExW(full_path.c_str(), GetFileExInfoStandard, &fa)) {
                    ev.size_bytes = ((int64_t)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
                    ev.sha256 = Sha256File(full_path);
                    ev.is_signed = IsFileSigned(full_path);
                }
            }

            ev.is_system_file = (dir_path.find(L"System32") != std::wstring::npos ||
                                  dir_path.find(L"system32") != std::wstring::npos);

            std::string risk_reason;
            ev.risk_score = AssessRisk(ev, risk_reason);
            ev.risk_reason = risk_reason;

            on_event(std::move(ev));

            if (info->NextEntryOffset == 0) break;
            ptr += info->NextEntryOffset;
        }
    }

    CancelIo(hDir);
    CloseHandle(hDir);
    CloseHandle(hEvent);
}

// ─── BuildSysWatchPage ─────────────────────────────────────────────────────────
QWidget* BuildSysWatchPage(QWidget* parent) {
    auto* page = new QWidget(parent);
    page->setObjectName("SysWatchPage");

    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(24, 20, 24, 20);
    root->setSpacing(16);

    // ── Header ────────────────────────────────────────────────────────────────
    auto* hdr = new QWidget;
    auto* hlay = new QHBoxLayout(hdr);
    hlay->setContentsMargins(0, 0, 0, 0);

    auto* title = new QLabel(QString::fromUtf8("System32 / Explorer Auto-Hunt"));
    title->setStyleSheet("color:#ECE4DA; font-size:28px; font-weight:700;");
    hlay->addWidget(title);
    hlay->addStretch();

    auto* live_dot = new QLabel;
    live_dot->setFixedSize(8, 8);
    live_dot->setStyleSheet("background:#4ADE80; border-radius:4px;");
    hlay->addWidget(live_dot);
    auto* live_lbl = new QLabel(QString::fromUtf8("Live Watch"));
    live_lbl->setStyleSheet("color:#4ADE80; font-size:12px; font-weight:600;");
    hlay->addWidget(live_lbl);

    auto* clear_btn = new QPushButton(QString::fromUtf8("Clear"));
    clear_btn->setFixedSize(80, 32);
    clear_btn->setStyleSheet(
        "QPushButton { background:#1C1108; border:1px solid #33261A; border-radius:7px; "
        "              color:#8B7355; font-size:12px; }"
        "QPushButton:hover { color:#ECE4DA; border-color:#FF7A00; }");
    hlay->addWidget(clear_btn);

    root->addWidget(hdr);

    // ── CPU-pegging alert (cryptojacking symptom: a process pinning the CPU) ──
    auto* cpu_banner = new QLabel(page);
    cpu_banner->setWordWrap(true);
    cpu_banner->setVisible(false);
    cpu_banner->setStyleSheet(
        "background:#2A0F0F; border:1px solid #FF5A6A; border-radius:10px;"
        "color:#FF9AA5; font-size:12px; font-weight:600; padding:10px 14px;");
    root->addWidget(cpu_banner);
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        const double ncpu = si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;
        auto prev = std::make_shared<std::unordered_map<DWORD, unsigned long long>>();
        auto prev_wall = std::make_shared<ULONGLONG>(0);

        auto* cpu_timer = new QTimer(page);
        cpu_timer->setInterval(5000);
        QObject::connect(cpu_timer, &QTimer::timeout, page, [cpu_banner, prev, prev_wall, ncpu]() {
            static const std::unordered_set<std::string> kMiners = {
                "xmrig.exe", "smrig.exe", "nbminer.exe", "phoenixminer.exe",
                "t-rex.exe", "lolminer.exe", "cpuminer.exe", "ccminer.exe",
                "nanominer.exe", "xmr-stak.exe", "srbminer-multi.exe",
            };
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE) return;
            std::unordered_map<DWORD, unsigned long long> cur;
            std::unordered_map<DWORD, std::string> names;
            PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (!h) continue;
                    FILETIME c, e, k, u;
                    if (GetProcessTimes(h, &c, &e, &k, &u)) {
                        ULARGE_INTEGER ku, uu;
                        ku.LowPart = k.dwLowDateTime; ku.HighPart = k.dwHighDateTime;
                        uu.LowPart = u.dwLowDateTime; uu.HighPart = u.dwHighDateTime;
                        cur[pe.th32ProcessID] = ku.QuadPart + uu.QuadPart;   // 100ns units
                        char nm[260];
                        int n = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                                    nm, sizeof(nm), nullptr, nullptr);
                        if (n > 0) names[pe.th32ProcessID] = nm;
                    }
                    CloseHandle(h);
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);

            const ULONGLONG now = GetTickCount64();
            const ULONGLONG wall_ms = (*prev_wall == 0) ? 0 : (now - *prev_wall);

            double best_pct = 0; DWORD best_pid = 0; std::string best_name;
            if (wall_ms > 0) {
                for (const auto& kv : cur) {
                    auto it = prev->find(kv.first);
                    if (it == prev->end()) continue;
                    const unsigned long long d = (kv.second >= it->second) ? kv.second - it->second : 0ull;
                    const double cpu_ms = d / 10000.0;                        // 100ns -> ms
                    const double pct = cpu_ms / (static_cast<double>(wall_ms) * ncpu) * 100.0;
                    if (pct > best_pct) {
                        best_pct = pct; best_pid = kv.first;
                        best_name = names.count(kv.first) ? names[kv.first] : std::string("?");
                    }
                }
            }
            *prev = std::move(cur);
            *prev_wall = now;

            if (best_pct >= 70.0 && best_pid != 0) {
                std::string lower = best_name;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                const bool is_miner = kMiners.count(lower) > 0;
                QString msg = is_miner
                    ? QString::fromUtf8("\xE2\x9A\xA0 Nghi CRYPTOMINER: ")
                    : QString::fromUtf8("\xE2\x9A\xA0 CPU b\xE1\xBB\x8B ghim: ");
                msg += QString::fromStdString(best_name)
                     + QString(" (PID %1) \xE2\x89\x88 ").arg(best_pid)
                     + QString::number(static_cast<int>(best_pct)) + "% CPU";
                cpu_banner->setText(msg);
                cpu_banner->setVisible(true);
            } else {
                cpu_banner->setVisible(false);
            }
        });
        cpu_timer->start();
    }

    // ── Watch targets ─────────────────────────────────────────────────────────
    auto* targets_card = new QWidget;
    targets_card->setStyleSheet("background:#1C1108; border:1px solid #33261A; border-radius:10px;");
    auto* tc = new QVBoxLayout(targets_card);
    tc->setContentsMargins(14, 10, 14, 10);
    tc->setSpacing(8);

    auto* tc_title = new QLabel(QString::fromUtf8("Watched Directories"));
    tc_title->setStyleSheet("color:#FF7A00; font-size:12px; font-weight:600;");
    tc->addWidget(tc_title);

    struct WatchTarget {
        const char* path;
        const char* label;
        bool        enabled;
    };

    static const WatchTarget kTargets[] = {
        { "C:\\Windows\\System32",      "System32 (kernel binaries)", true },
        { "C:\\Windows\\SysWOW64",      "SysWOW64",                   true },
        { "C:\\Windows",                "Windows root (drivers, etc)",  false },
        { "C:\\Windows\\Prefetch",      "Prefetch (execution traces)", false },
        { "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                                        "User Startup folder",         true },
        { "HKLM_RunKey_Sentinel",       "HKLM Run keys (virtual)",     false },
    };

    auto* targets_row = new QHBoxLayout;
    targets_row->setSpacing(8);

    std::vector<QCheckBox*> target_checks;
    for (const auto& t : kTargets) {
        auto* cb = new QCheckBox(QString::fromUtf8(t.label));
        cb->setChecked(t.enabled);
        cb->setStyleSheet("color:#C7B6A2; font-size:11px;");
        targets_row->addWidget(cb);
        target_checks.push_back(cb);
    }
    targets_row->addStretch();
    tc->addLayout(targets_row);
    root->addWidget(targets_card);

    // ── Stat cards ────────────────────────────────────────────────────────────
    auto* cards_row = new QHBoxLayout;
    cards_row->setSpacing(10);

    static QLabel* s_total = nullptr;
    static QLabel* s_high  = nullptr;
    static QLabel* s_new   = nullptr;
    static QLabel* s_quarantined = nullptr;

    auto makeStatCard = [&](const char* title, const char* color, QLabel** out) {
        auto* card = new QWidget;
        card->setFixedHeight(68);
        card->setStyleSheet("background:#1C1108; border:1px solid #33261A; border-radius:10px;");
        auto* cl = new QVBoxLayout(card);
        cl->setContentsMargins(14, 8, 14, 8);
        cl->setSpacing(3);
        auto* val = new QLabel("0");
        val->setStyleSheet(QString("color:%1; font-size:22px; font-weight:700;").arg(color));
        *out = val;
        cl->addWidget(val);
        auto* lbl = new QLabel(QString::fromUtf8(title));
        lbl->setStyleSheet("color:#8B7355; font-size:11px;");
        cl->addWidget(lbl);
        cards_row->addWidget(card, 1);
    };

    makeStatCard("Total Events",     "#ECE4DA",  &s_total);
    makeStatCard("High Risk",        "#FF5A6A",  &s_high);
    makeStatCard("New Files",        "#FF7A00",  &s_new);
    makeStatCard("Quarantined",      "#4ADE80",  &s_quarantined);
    root->addLayout(cards_row);

    // ── Event table ───────────────────────────────────────────────────────────
    auto* tbl_card = new QWidget;
    tbl_card->setStyleSheet("background:#1C1108; border:1px solid #33261A; border-radius:12px;");
    auto* tcl = new QVBoxLayout(tbl_card);
    tcl->setContentsMargins(0, 0, 0, 0);

    auto* tbl = new QTableWidget(0, 6);
    tbl->setObjectName("SysWatchTable");
    tbl->setHorizontalHeaderLabels({
        "Risk", "Time", "Action", "Filename", "Path", "Signed"
    });
    tbl->horizontalHeader()->setStretchLastSection(false);
    tbl->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    tbl->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    tbl->setColumnWidth(0, 48);
    tbl->setColumnWidth(1, 80);
    tbl->setColumnWidth(2, 72);
    tbl->setColumnWidth(5, 56);
    tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tbl->setShowGrid(false);
    tbl->verticalHeader()->hide();
    tbl->setStyleSheet(
        "QTableWidget { background:transparent; color:#ECE4DA; font-size:12px; "
        "               border:none; selection-background-color:#FF7A0025; }"
        "QTableWidget::item { padding:5px 8px; border-bottom:1px solid #1C1108; }"
        "QHeaderView::section { background:#0E0804; color:#8B7355; font-size:11px; "
        "                       padding:5px; border:none; border-bottom:1px solid #33261A; }");
    tcl->addWidget(tbl);
    root->addWidget(tbl_card, 1);

    // Export the live-watch log to CSV. Added next to Clear in the header row;
    // enabled whenever there are rows to save.
    auto* export_btn = MakeExportButton(page, tbl,
                                        QString::fromUtf8("syswatch_log.csv"));
    export_btn->setFixedHeight(32);
    hlay->addWidget(export_btn);
    auto* export_sync = new QTimer(page);
    export_sync->setInterval(400);
    QObject::connect(export_sync, &QTimer::timeout, export_btn, [export_btn, tbl]() {
        export_btn->setEnabled(tbl->rowCount() > 0);
    });
    export_sync->start();

    // ── Detail + action panel ─────────────────────────────────────────────────
    auto* detail = new QWidget;
    detail->setMaximumHeight(0);
    detail->setStyleSheet("background:#1C1108; border:1px solid #FF7A0040; border-radius:10px;");
    auto* dl = new QVBoxLayout(detail);
    dl->setContentsMargins(14, 10, 14, 10);
    dl->setSpacing(8);

    auto* detail_text = new QTextEdit;
    detail_text->setReadOnly(true);
    detail_text->setMaximumHeight(90);
    detail_text->setStyleSheet("QTextEdit { background:transparent; color:#C7B6A2; font-size:12px; border:none; }");
    dl->addWidget(detail_text);

    auto* act_row = new QHBoxLayout;
    auto makeDBtn = [&](const char* label, const char* color_hex) {
        auto* b = new QPushButton(QString::fromUtf8(label));
        b->setFixedHeight(30);
        const QString c = QString::fromUtf8(color_hex);
        b->setStyleSheet(QString(
            "QPushButton { background:%1; border:1px solid %2; border-radius:6px; "
            "              color:%2; font-size:12px; padding:0 12px; }"
            "QPushButton:hover { background:%3; }")
            .arg(c + "30")
            .arg(c)
            .arg(c + "50"));
        act_row->addWidget(b);
        return b;
    };
    auto* quarantine_btn = makeDBtn("Quarantine File", "#FF7A00");
    auto* reveal_btn     = makeDBtn("Reveal in Explorer", "#4DB8FF");
    auto* vt_btn         = makeDBtn("VirusTotal Lookup", "#4DB8FF");
    act_row->addStretch();
    dl->addLayout(act_row);
    root->addWidget(detail);

    // ── Shared state ──────────────────────────────────────────────────────────
    struct WatchState {
        std::vector<SysWatchEvent> events;
        std::unordered_map<std::string, int> path_index; // full path -> events/row index
        std::unordered_set<std::string> enqueued; // paths already sent to Auto-Hunt (dedup)
        std::mutex mtx;
        std::atomic<bool> stop{false};
        int selected_idx = -1;
        int n_high = 0;
        int n_new = 0;
        int n_quarantined = 0;
    };
    auto* ws = new WatchState;
    ArmQuitGuard(page);

    // ── Row fill / insert helpers ─────────────────────────────────────────────
    // Sys Watch dedups by path (see watcher callback): one file = one row that
    // is refreshed in place instead of being appended again on every filesystem
    // event, so the list no longer repeats the same file over and over.
    auto fillEventRow = [=](int row, const SysWatchEvent& ev) {
        const QColor risk_col = (ev.risk_score >= 70) ? QColor(0xFF,0x5A,0x6A)
                               : (ev.risk_score >= 40) ? QColor(0xFF,0x7A,0x00)
                                                       : QColor(0x4A,0xDE,0x80);

        // Risk dot
        auto* dot_w = new QWidget;
        auto* dl2 = new QHBoxLayout(dot_w);
        dl2->setContentsMargins(8,0,0,0);
        auto* dot = new QLabel;
        dot->setFixedSize(10,10);
        dot->setStyleSheet(QString("background:%1; border-radius:5px;").arg(risk_col.name()));
        dl2->addWidget(dot);
        tbl->setCellWidget(row, 0, dot_w);

        // Format timestamp
        SYSTEMTIME st;
        FileTimeToSystemTime(&ev.timestamp, &st);
        const QString ts = QString("%1:%2:%3")
            .arg(st.wHour, 2, 10, QLatin1Char('0'))
            .arg(st.wMinute, 2, 10, QLatin1Char('0'))
            .arg(st.wSecond, 2, 10, QLatin1Char('0'));

        const char* action_str = (ev.action == SysWatchEvent::Created)  ? "Created"
                                : (ev.action == SysWatchEvent::Modified) ? "Modified"
                                : (ev.action == SysWatchEvent::Deleted)  ? "Deleted"
                                                                          : "Renamed";

        auto mkItem = [](const QString& s, QColor c = QColor(0xE8,0xE8,0xE8)) {
            auto* item = new QTableWidgetItem(s);
            item->setForeground(c);
            return item;
        };

        tbl->setItem(row, 1, mkItem(ts, QColor(0x8B,0x8B,0x8B)));
        tbl->setItem(row, 2, mkItem(QString::fromUtf8(action_str),
            ev.action == SysWatchEvent::Created ? QColor(0xFF,0x7A,0x00) :
            ev.action == SysWatchEvent::Deleted ? QColor(0xFF,0x5A,0x6A) :
            QColor(0xE8,0xE8,0xE8)));
        tbl->setItem(row, 3, mkItem(QString::fromStdString(ev.filename), risk_col));
        tbl->setItem(row, 4, mkItem(QString::fromStdString(ev.path), QColor(0x8B,0x8B,0x8B)));
        tbl->setItem(row, 5, mkItem(ev.is_signed ? "Yes" : "No",
            ev.is_signed ? QColor(0x4A,0xDE,0x80) : QColor(0xFF,0x5A,0x6A)));
        tbl->setRowHeight(row, 34);
        tbl->item(row, 3)->setData(Qt::UserRole, row);
    };

    auto addEventRow = [=](const SysWatchEvent& ev) {
        const int row = tbl->rowCount();
        tbl->insertRow(row);
        fillEventRow(row, ev);
        tbl->scrollToBottom();
    };

    // ── Launch watcher threads ────────────────────────────────────────────────
    static const wchar_t* kWatchDirs[] = {
        L"C:\\Windows\\System32",
        L"C:\\Windows\\SysWOW64",
        nullptr
    };

    for (int i = 0; kWatchDirs[i]; ++i) {
        const std::wstring dir(kWatchDirs[i]);
        std::thread([=] {
            WatchThread(dir, ws->stop, [=](SysWatchEvent ev) {
                std::lock_guard<std::mutex> lk(ws->mtx);
                if (AppQuitting().load()) return;

                // Feed high-risk events to the AI Auto-Hunt queue, but at most
                // ONCE per path. System32/SysWOW64 files fire a steady stream of
                // Modified events; the old code enqueued on every single one,
                // flooding the hunt queue with duplicates and re-scanning the same
                // file over and over -- a self-sustaining churn that pegged CPU.
                // The enqueued-set gates it so each file is hunted once (reset on
                // Clear). Was previously called outside the lock too; now under it.
                if (ev.risk_score >= 45 && ws->enqueued.insert(ev.path).second) {
                    HuntTarget ht;
                    ht.source      = "Sys Watch";
                    ht.name        = ev.filename;
                    ht.path        = ev.path;
                    ht.risk_score  = ev.risk_score;
                    ht.description = ev.risk_reason.empty() ? "System32 file change" : ev.risk_reason;
                    AutoHuntEnqueue(std::move(ht));
                }

                // Dedup by path: the same file often fires several FS events in a
                // row (Created + Modified, or repeated Modified). Refresh the
                // existing row in place instead of appending a duplicate.

                if (auto it = ws->path_index.find(ev.path); it != ws->path_index.end()) {
                    const int idx = it->second;
                    ws->events[idx] = ev;
                    // ws->events is written by two watcher threads (System32 +
                    // SysWOW64) concurrently under ws->mtx. This lambda runs
                    // later on the GUI thread via the event queue, so it must
                    // re-take the same lock before touching ws->events --
                    // otherwise a concurrent push_back on another thread can
                    // reallocate/move the vector's buffer out from under this
                    // read, corrupting the std::string members mid-copy
                    // (reliably crashed with a use-after-free inside
                    // QString::fromStdString -> strlen on freed memory).
                    QMetaObject::invokeMethod(tbl, [=] {
                        if (AppQuitting().load()) return;
                        std::lock_guard<std::mutex> glk(ws->mtx);
                        if (idx < 0 || idx >= (int)ws->events.size()) return;
                        fillEventRow(idx, ws->events[idx]);
                    }, Qt::QueuedConnection);
                    return;
                }

                if (ev.risk_score >= 70) ws->n_high++;
                if (ev.action == SysWatchEvent::Created) ws->n_new++;
                const int idx = static_cast<int>(ws->events.size());
                ws->events.push_back(ev);
                ws->path_index.emplace(ev.path, idx);

                QMetaObject::invokeMethod(tbl, [=] {
                    if (AppQuitting().load()) return;
                    std::lock_guard<std::mutex> glk(ws->mtx);
                    if (idx < 0 || idx >= (int)ws->events.size()) return;
                    addEventRow(ws->events[idx]);
                    const int total = static_cast<int>(ws->events.size());
                    if (s_total) s_total->setText(QString::number(total));
                    if (s_high)  s_high->setText(QString::number(ws->n_high));
                    if (s_new)   s_new->setText(QString::number(ws->n_new));
                }, Qt::QueuedConnection);
            });
        }).detach();
    }

    // ── Row selection → detail panel ──────────────────────────────────────────
    QObject::connect(tbl, &QTableWidget::currentCellChanged, tbl,
        [=](int row, int, int, int) {
            if (row < 0) return;
            auto* item = tbl->item(row, 3);
            if (!item) return;
            const int idx = item->data(Qt::UserRole).toInt();
            std::lock_guard<std::mutex> lk(ws->mtx);
            if (idx < 0 || idx >= (int)ws->events.size()) return;
            const auto& ev = ws->events[idx];
            ws->selected_idx = idx;
            detail_text->setText(QString(
                "<b>File:</b> %1<br>"
                "<b>Full path:</b> %2<br>"
                "<b>Size:</b> %3 bytes<br>"
                "<b>SHA-256:</b> <code>%4</code><br>"
                "<b>Signed:</b> %5 &nbsp; <b>Risk score:</b> %6<br>"
                "<b>Reason:</b> %7")
                .arg(QString::fromStdString(ev.filename))
                .arg(QString::fromStdString(ev.path))
                .arg(ev.size_bytes)
                .arg(QString::fromStdString(ev.sha256))
                .arg(ev.is_signed ? "Yes" : "No")
                .arg(ev.risk_score)
                .arg(QString::fromStdString(ev.risk_reason)));
            detail->setMaximumHeight(180);
        });

    // ── Quarantine action ─────────────────────────────────────────────────────
    QObject::connect(quarantine_btn, &QPushButton::clicked, quarantine_btn, [=] {
        std::lock_guard<std::mutex> lk(ws->mtx);
        if (ws->selected_idx < 0 || ws->selected_idx >= (int)ws->events.size()) return;
        auto& ev = ws->events[ws->selected_idx];
        if (ev.quarantined) return;

        // Move file to quarantine dir
        const std::wstring src = [&] {
            std::wstring w;
            w.resize(ev.path.size() + 1);
            MultiByteToWideChar(CP_UTF8, 0, ev.path.c_str(), -1, w.data(), (int)w.size());
            return w;
        }();
        const std::wstring dst = L"C:\\ProgramData\\TeoAVSuite\\Quarantine\\" +
            std::filesystem::path(src).filename().wstring() + L".quarantine";

        CreateDirectoryW(L"C:\\ProgramData\\TeoAVSuite\\Quarantine", nullptr);
        if (MoveFileExW(src.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            ev.quarantined = true;
            ws->n_quarantined++;
            if (s_quarantined) s_quarantined->setText(QString::number(ws->n_quarantined));
        }
    });

    // ── Reveal in Explorer ────────────────────────────────────────────────────
    QObject::connect(reveal_btn, &QPushButton::clicked, reveal_btn, [=] {
        std::lock_guard<std::mutex> lk(ws->mtx);
        if (ws->selected_idx < 0 || ws->selected_idx >= (int)ws->events.size()) return;
        const auto& ev = ws->events[ws->selected_idx];
        std::wstring path;
        path.resize(ev.path.size() + 1);
        MultiByteToWideChar(CP_UTF8, 0, ev.path.c_str(), -1, path.data(), (int)path.size());
        PIDLIST_ABSOLUTE pidl = ILCreateFromPathW(path.c_str());
        if (pidl) {
            SHOpenFolderAndSelectItems(pidl, 0, nullptr, 0);
            ILFree(pidl);
        }
    });

    // ── VirusTotal lookup ─────────────────────────────────────────────────────
    QObject::connect(vt_btn, &QPushButton::clicked, vt_btn, [=] {
        QString sha256;
        {
            std::lock_guard<std::mutex> lk(ws->mtx);
            if (ws->selected_idx < 0 || ws->selected_idx >= (int)ws->events.size()) {
                QMessageBox::information(page, "VirusTotal",
                    QString::fromUtf8("Ch\xe1\xbb\x8dn m\xe1\xbb\x99t d\xc3\xb2ng trong b\xe1\xba\xa3ng tr\xc6\xb0\xe1\xbb\x9b""c."));
                return;
            }
            sha256 = QString::fromStdString(ws->events[ws->selected_idx].sha256);
        }
        if (sha256.isEmpty()) {
            QMessageBox::information(page, "VirusTotal",
                QString::fromUtf8("File n\xc3\xa0y ch\xc6\xb0""a c\xc3\xb3 SHA-256 (ch\xc6\xb0""a hash xong)."));
            return;
        }
        auto* mw = qobject_cast<MainWindow*>(parent);
        if (!mw) return;
        vt_btn->setEnabled(false);
        std::thread([mw, sha256, vt_btn] {
            const QString result = mw->LookupVtIoc("hash", sha256);
            if (AppQuitting().load()) return;
            QMetaObject::invokeMethod(mw, [mw, result, vt_btn] {
                vt_btn->setEnabled(true);
                QMessageBox::information(mw, "VirusTotal", result);
            }, Qt::QueuedConnection);
        }).detach();
    });

    // ── Clear events ──────────────────────────────────────────────────────────
    QObject::connect(clear_btn, &QPushButton::clicked, clear_btn, [=] {
        std::lock_guard<std::mutex> lk(ws->mtx);
        ws->events.clear();
        ws->path_index.clear();
        ws->enqueued.clear();
        ws->n_high = ws->n_new = ws->n_quarantined = 0;
        tbl->setRowCount(0);
        if (s_total)       s_total->setText("0");
        if (s_high)        s_high->setText("0");
        if (s_new)         s_new->setText("0");
        if (s_quarantined) s_quarantined->setText("0");
        detail->setMaximumHeight(0);
    });

    // Pulse the live dot
    auto* dot_timer = new QTimer(page);
    bool dot_visible = true;
    QObject::connect(dot_timer, &QTimer::timeout, live_dot, [=]() mutable {
        dot_visible = !dot_visible;
        live_dot->setStyleSheet(
            dot_visible ? "background:#4ADE80; border-radius:4px;"
                        : "background:#33261A; border-radius:4px;");
    });
    dot_timer->start(800);

    // Signal watch threads to stop. Threads hold raw pointer so don't delete ws
    // here — threads will exit their loop and the OS reclaims memory on exit.
    QObject::connect(page, &QObject::destroyed, page, [ws] {
        ws->stop.store(true);
    });

    return page;
}

} // namespace avdashboard
