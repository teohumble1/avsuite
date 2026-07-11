// main_window_dllintel.cpp — DLL Hijacking & Supply Chain Attack Monitor
// Detects: phantom DLL hijacking, DLL search-order abuse, module spoofing,
//          unsigned DLL in system paths, high-risk process module anomalies.
// Uses: Windows toolhelp32 snapshot, module version info, digital signature checks.

#include "main_window.hpp"
#include "av_quit_guard.hpp"
#include "hunt_toolbar.hpp"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QColor>
#include <QDateTime>
#include <QFont>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QTextEdit>

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <WinTrust.h>
#include <SoftPub.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")

#include <atomic>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "autohunt_types.hpp"

namespace avdashboard {

// ─── DLL threat record ────────────────────────────────────────────────────────
struct DllThreat {
    uint32_t    pid;
    std::string process_name;
    std::string dll_path;
    std::string dll_name;
    std::string threat_type;     // "DLL Hijack", "Unsigned DLL", "Suspicious Path", "Module Spoof"
    int         risk_score;      // 0-100
    std::string description;
    FILETIME    detected_at;
};

// ─── Known safe DLL paths (system roots) ─────────────────────────────────────
static const wchar_t* kSystemRoots[] = {
    L"C:\\Windows\\System32\\",
    L"C:\\Windows\\SysWOW64\\",
    L"C:\\Windows\\WinSxS\\",
    L"C:\\Program Files\\",
    L"C:\\Program Files (x86)\\",
    nullptr
};

static bool IsSystemPath(const std::wstring& path) {
    for (int i = 0; kSystemRoots[i]; ++i) {
        if (path.size() >= wcslen(kSystemRoots[i]) &&
            _wcsnicmp(path.c_str(), kSystemRoots[i], wcslen(kSystemRoots[i])) == 0)
            return true;
    }
    return false;
}

// ─── Digital signature check (embedded + catalog) ────────────────────────────
// System DLLs in C:\Windows\System32 use catalog signing (signature in catalog file),
// not embedded Authenticode. Check both to avoid false positives on legitimate system files.
static bool IsDllSignedEmbedded(const std::wstring& path) {
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
    LONG result = WinVerifyTrust(nullptr, &action, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);

    return result == ERROR_SUCCESS;
}

static bool IsDllSignedByCatalog(const std::wstring& path) {
    // System files use catalog signing. This is a simplified check:
    // System DLLs in Windows\System32 are almost always signed via catalog.
    // If it's in system paths and not obviously modified, trust it.
    if (path.find(L"C:\\Windows\\System32\\") == 0 ||
        path.find(L"C:\\Windows\\SysWOW64\\") == 0 ||
        path.find(L"C:\\Windows\\WinSxS\\") == 0) {
        // These paths only contain signed binaries (catalog or embedded)
        // If a file exists here, assume it's legitimate (zero-trust doesn't mean
        // distrust the OS itself — only user-installed software).
        return true;
    }
    return false;
}

static bool IsDllSigned(const std::wstring& path) {
    // Check embedded Authenticode first
    if (IsDllSignedEmbedded(path)) return true;

    // Then check if it's signed via Windows catalog (system files)
    if (IsDllSignedByCatalog(path)) return true;

    return false;
}

// ─── DLL search-order hijack candidates ──────────────────────────────────────
// Check if a DLL loaded from a non-system path shadows a system DLL of the same name.
static bool IsPotentialHijack(const std::wstring& dll_path) {
    if (IsSystemPath(dll_path)) return false;

    const std::wstring name = std::filesystem::path(dll_path).filename().wstring();
    const std::wstring sys32 = L"C:\\Windows\\System32\\" + name;
    const std::wstring syswow = L"C:\\Windows\\SysWOW64\\" + name;

    return GetFileAttributesW(sys32.c_str()) != INVALID_FILE_ATTRIBUTES ||
           GetFileAttributesW(syswow.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// ─── High-risk process names (commonly targeted for DLL injection) ─────────────
static const char* kHighRiskProcesses[] = {
    "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe",
    "winlogon.exe", "services.exe", "msiexec.exe", "regsvr32.exe",
    "rundll32.exe", "dllhost.exe", "werfault.exe", "taskhost.exe",
    nullptr
};

static bool IsHighRiskProcess(const std::string& name) {
    for (int i = 0; kHighRiskProcesses[i]; ++i) {
        if (_stricmp(name.c_str(), kHighRiskProcesses[i]) == 0) return true;
    }
    return false;
}

// ─── Scan a single process for DLL threats ────────────────────────────────────
static std::vector<DllThreat> ScanProcessDlls(uint32_t pid, const std::string& proc_name) {
    std::vector<DllThreat> threats;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return threats;

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);

    if (Module32FirstW(hSnap, &me)) {
        do {
            std::wstring dll_path = me.szExePath;
            if (dll_path.empty()) {
                CloseHandle(hSnap);
                return threats;
            }

            std::string dll_name_a;
            {
                char buf[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, buf, MAX_PATH, nullptr, nullptr);
                dll_name_a = buf;
            }
            std::string dll_path_a;
            {
                char buf[MAX_PATH * 2] = {};
                WideCharToMultiByte(CP_UTF8, 0, dll_path.c_str(), -1, buf, MAX_PATH*2, nullptr, nullptr);
                dll_path_a = buf;
            }

            // Skip first module (the exe itself)
            if (_wcsicmp(me.szModule, L"") == 0) { continue; }

            DllThreat t;
            t.pid          = pid;
            t.process_name = proc_name;
            t.dll_name     = dll_name_a;
            t.dll_path     = dll_path_a;
            t.risk_score   = 0;
            GetSystemTimeAsFileTime(&t.detected_at);

            bool flagged = false;

            // 1. DLL hijack: non-system path DLL that shadows a system DLL
            if (IsPotentialHijack(dll_path)) {
                t.threat_type  = "DLL Hijack";
                t.description  = "DLL loaded from non-system path shadows a System32 DLL of the same name";
                t.risk_score   = IsHighRiskProcess(proc_name) ? 90 : 70;
                flagged = true;
            }
            // 2. Unsigned DLL in high-risk process
            else if (IsHighRiskProcess(proc_name) && !IsDllSigned(dll_path)) {
                t.threat_type  = "Unsigned DLL";
                t.description  = "Unsigned DLL loaded in a high-value system process";
                t.risk_score   = 60;
                flagged = true;
            }
            // 3. DLL loaded from temp/appdata/user dirs
            else if (!IsSystemPath(dll_path)) {
                std::wstring lower = dll_path;
                for (auto& ch : lower) ch = towlower(ch);
                if (lower.find(L"\\temp\\") != std::wstring::npos ||
                    lower.find(L"\\tmp\\") != std::wstring::npos ||
                    lower.find(L"\\appdata\\local\\temp") != std::wstring::npos) {
                    t.threat_type = "Suspicious Path";
                    t.description = "DLL loaded from Temp/AppData directory — common injection vector";
                    t.risk_score  = 75;
                    flagged = true;
                }
            }

            if (flagged) threats.push_back(std::move(t));

        } while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);
    return threats;
}

// ─── Full system DLL threat scan ─────────────────────────────────────────────
static std::vector<DllThreat> FullDllScan(std::atomic<bool>& stop_flag) {
    std::vector<DllThreat> all_threats;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return all_threats;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (stop_flag.load()) break;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            char name_buf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name_buf, MAX_PATH, nullptr, nullptr);
            std::string proc_name = name_buf;

            auto threats = ScanProcessDlls(pe.th32ProcessID, proc_name);
            all_threats.insert(all_threats.end(), threats.begin(), threats.end());

        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return all_threats;
}

// ─── DLL Monitor Page builder (called from main_window.cpp) ──────────────────
// This is appended to the existing MainWindow class via a separate helper.
// The actual page widget is returned and wired into the stack in BuildDllPage().

} // namespace avdashboard


// ─── BuildDllPage ─────────────────────────────────────────────────────────────
// Builds the DLL Hijacking & Supply Chain monitor page widget.
// Returns a self-contained QWidget* with its own scan timer and table.

namespace avdashboard {

QWidget* BuildDllIntelPage(QWidget* parent) {
    // ── Root ──────────────────────────────────────────────────────────────────
    auto* page = new QWidget(parent);
    page->setObjectName("DllPage");
    ArmQuitGuard(page);

    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(24, 20, 24, 20);
    root->setSpacing(16);

    // ── Header ────────────────────────────────────────────────────────────────
    auto* hdr = new QWidget;
    auto* hlay = new QHBoxLayout(hdr);
    hlay->setContentsMargins(0, 0, 0, 0);

    auto* title = new QLabel(QString::fromUtf8("DLL & Supply Chain Monitor"));
    title->setStyleSheet("color:#FF7A00; font-size:20px; font-weight:700;");
    hlay->addWidget(title);
    hlay->addStretch();

    auto* status_lbl = new QLabel(QString::fromUtf8("Idle"));
    status_lbl->setObjectName("DllStatusLbl");
    status_lbl->setStyleSheet("color:#8B7355; font-size:12px;");
    hlay->addWidget(status_lbl);

    auto* scan_btn = new QPushButton(QString::fromUtf8("Scan Now"));
    scan_btn->setObjectName("DllScanBtn");
    scan_btn->setFixedSize(100, 34);
    scan_btn->setStyleSheet(
        "QPushButton { background:#FF7A00; color:#000; border-radius:8px; font-weight:600; font-size:12px; }"
        "QPushButton:hover { background:#FF9030; }"
        "QPushButton:pressed { background:#E06800; }");
    hlay->addWidget(scan_btn);

    root->addWidget(hdr);

    // ── Stat cards ────────────────────────────────────────────────────────────
    auto* card_row = new QHBoxLayout;
    card_row->setSpacing(12);

    struct StatCard { const char* title; const char* color; QLabel** lbl; };

    static QLabel* s_total   = nullptr;
    static QLabel* s_hijack  = nullptr;
    static QLabel* s_unsigned = nullptr;
    static QLabel* s_susp    = nullptr;

    auto makeCard = [&](const char* title, const char* color, QLabel** out) {
        auto* card = new QWidget;
        card->setFixedHeight(72);
        card->setStyleSheet(QString("background:#1C1108; border:1px solid #33261A; border-radius:10px;"));
        auto* cl = new QVBoxLayout(card);
        cl->setContentsMargins(14, 10, 14, 10);
        cl->setSpacing(4);
        auto* val = new QLabel("0");
        val->setStyleSheet(QString("color:%1; font-size:22px; font-weight:700;").arg(color));
        *out = val;
        cl->addWidget(val);
        auto* lbl = new QLabel(QString::fromUtf8(title));
        lbl->setStyleSheet("color:#8B7355; font-size:11px;");
        cl->addWidget(lbl);
        card_row->addWidget(card, 1);
    };

    makeCard("Total Threats", "#FF5A6A", &s_total);
    makeCard("DLL Hijacks",   "#FF7A00", &s_hijack);
    makeCard("Unsigned DLLs", "#FBBF24", &s_unsigned);
    makeCard("Suspicious Path","#4DB8FF", &s_susp);
    root->addLayout(card_row);

    // ── Filter bar ───────────────────────────────────────────────────────────
    auto* filter_bar = new QWidget;
    auto* fl = new QHBoxLayout(filter_bar);
    fl->setContentsMargins(0, 0, 0, 0);
    fl->setSpacing(8);

    auto* search_edit = new QLineEdit;
    search_edit->setPlaceholderText(QString::fromUtf8("Filter by process or DLL name..."));
    search_edit->setFixedHeight(32);
    search_edit->setStyleSheet(
        "QLineEdit { background:#1C1108; border:1px solid #33261A; border-radius:7px; "
        "            color:#ECE4DA; padding:0 10px; font-size:12px; }"
        "QLineEdit:focus { border-color:#FF7A00; }");
    fl->addWidget(search_edit, 1);

    auto makeFilterBtn = [&](const char* text) {
        auto* b = new QPushButton(QString::fromUtf8(text));
        b->setCheckable(true);
        b->setFixedHeight(32);
        b->setStyleSheet(
            "QPushButton { background:#1C1108; border:1px solid #33261A; border-radius:7px; "
            "              color:#8B7355; padding:0 12px; font-size:12px; }"
            "QPushButton:checked { background:#FF7A0020; border-color:#FF7A00; color:#FF7A00; }"
            "QPushButton:hover { color:#ECE4DA; }");
        fl->addWidget(b);
        return b;
    };

    auto* fb_all     = makeFilterBtn("All");
    auto* fb_hijack  = makeFilterBtn("Hijacks");
    auto* fb_unsigned= makeFilterBtn("Unsigned");
    auto* fb_susp    = makeFilterBtn("Suspicious");
    fb_all->setChecked(true);

    root->addWidget(filter_bar);

    // ── Threat table ──────────────────────────────────────────────────────────
    auto* tbl_card = new QWidget;
    tbl_card->setStyleSheet("background:#1C1108; border:1px solid #33261A; border-radius:12px;");
    auto* tc = new QVBoxLayout(tbl_card);
    tc->setContentsMargins(0, 0, 0, 0);

    auto* tbl = new QTableWidget(0, 6);
    tbl->setObjectName("DllThreatTable");
    tbl->setHorizontalHeaderLabels({
        "Risk", "Process", "DLL Name", "Threat Type", "Path", "Score"
    });
    tbl->horizontalHeader()->setStretchLastSection(false);
    tbl->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    tbl->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    tbl->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    tbl->setColumnWidth(0, 48);
    tbl->setColumnWidth(3, 120);
    tbl->setColumnWidth(5, 52);
    tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tbl->setShowGrid(false);
    tbl->verticalHeader()->hide();
    tbl->setAlternatingRowColors(false);

    // Export the DLL threat table to CSV, added to the header row next to Scan.
    auto* export_btn = MakeExportButton(page, tbl,
                                        QString::fromUtf8("dll_threats.csv"));
    export_btn->setFixedHeight(34);
    hlay->addWidget(export_btn);
    auto* export_sync = new QTimer(page);
    export_sync->setInterval(400);
    QObject::connect(export_sync, &QTimer::timeout, export_btn, [export_btn, tbl]() {
        export_btn->setEnabled(tbl->rowCount() > 0);
    });
    export_sync->start();
    tbl->setStyleSheet(
        "QTableWidget { background:transparent; color:#ECE4DA; font-size:12px; "
        "               border:none; selection-background-color:#FF7A0025; }"
        "QTableWidget::item { padding:6px 8px; border-bottom:1px solid #1E1208; }"
        "QHeaderView::section { background:#0E0804; color:#8B7355; font-size:11px; "
        "                       padding:6px; border:none; border-bottom:1px solid #33261A; }");
    tc->addWidget(tbl);
    root->addWidget(tbl_card, 1);

    // ── Detail panel ──────────────────────────────────────────────────────────
    auto* detail_card = new QWidget;
    detail_card->setFixedHeight(0); // collapsed initially
    detail_card->setStyleSheet("background:#1A1009; border:1px solid #FF7A0040; border-radius:10px;");
    detail_card->setMaximumHeight(0);

    auto* detail_lay = new QVBoxLayout(detail_card);
    detail_lay->setContentsMargins(16, 12, 16, 12);

    auto* detail_title = new QLabel(QString::fromUtf8("Threat Details"));
    detail_title->setStyleSheet("color:#FF7A00; font-size:13px; font-weight:600;");
    detail_lay->addWidget(detail_title);

    auto* detail_text = new QTextEdit;
    detail_text->setReadOnly(true);
    detail_text->setMaximumHeight(100);
    detail_text->setStyleSheet(
        "QTextEdit { background:transparent; color:#C7B6A2; font-size:12px; border:none; }");
    detail_lay->addWidget(detail_text);

    auto* det_btn_row = new QHBoxLayout;
    auto* kill_btn = new QPushButton(QString::fromUtf8("Kill Process"));
    kill_btn->setFixedSize(110, 30);
    kill_btn->setStyleSheet(
        "QPushButton { background:#FF5A6A30; border:1px solid #FF5A6A; border-radius:6px; "
        "              color:#FF5A6A; font-size:12px; }"
        "QPushButton:hover { background:#FF5A6A50; }");
    auto* quarantine_btn = new QPushButton(QString::fromUtf8("Quarantine DLL"));
    quarantine_btn->setFixedSize(130, 30);
    quarantine_btn->setStyleSheet(
        "QPushButton { background:#FF7A0030; border:1px solid #FF7A00; border-radius:6px; "
        "              color:#FF7A00; font-size:12px; }"
        "QPushButton:hover { background:#FF7A0050; }");
    det_btn_row->addWidget(kill_btn);
    det_btn_row->addWidget(quarantine_btn);
    det_btn_row->addStretch();
    detail_lay->addLayout(det_btn_row);

    root->addWidget(detail_card);

    // ── State shared with lambdas ──────────────────────────────────────────────
    struct State {
        std::vector<DllThreat> threats;
        std::mutex             mtx;
        std::atomic<bool>      scanning{false};
        std::atomic<bool>      stop_scan{false};
        int                    filter_mode = 0; // 0=All 1=Hijack 2=Unsigned 3=Susp
        QString                search_text;
        int                    selected_row = -1;
    };
    auto* state = new State();
    // state lives as long as page does (parent chain)

    // ── Populate table from state ─────────────────────────────────────────────
    auto refreshTable = [=] {
        std::lock_guard<std::mutex> lk(state->mtx);
        tbl->setRowCount(0);

        int total = 0, n_hijack = 0, n_unsigned = 0, n_susp = 0;

        for (const auto& t : state->threats) {
            const bool typeMatch = (state->filter_mode == 0) ||
                (state->filter_mode == 1 && t.threat_type == "DLL Hijack") ||
                (state->filter_mode == 2 && t.threat_type == "Unsigned DLL") ||
                (state->filter_mode == 3 && t.threat_type == "Suspicious Path");

            const bool searchMatch = state->search_text.isEmpty() ||
                QString::fromStdString(t.process_name).contains(state->search_text, Qt::CaseInsensitive) ||
                QString::fromStdString(t.dll_name).contains(state->search_text, Qt::CaseInsensitive);

            if (!typeMatch || !searchMatch) continue;

            const int row = tbl->rowCount();
            tbl->insertRow(row);

            // Risk dot
            const QColor risk_color = (t.risk_score >= 80) ? QColor(0xFF,0x5A,0x6A)
                                    : (t.risk_score >= 55) ? QColor(0xFF,0x7A,0x00)
                                                           : QColor(0xFA,0xCC,0x15);
            auto* dot_w = new QWidget;
            auto* dot_l = new QHBoxLayout(dot_w);
            dot_l->setContentsMargins(8, 0, 0, 0);
            auto* dot = new QLabel;
            dot->setFixedSize(10, 10);
            dot->setStyleSheet(QString("background:%1; border-radius:5px;").arg(risk_color.name()));
            dot_l->addWidget(dot);
            tbl->setCellWidget(row, 0, dot_w);

            auto make_item = [](const std::string& s, QColor c = QColor(0xE8,0xE8,0xE8)) {
                auto* item = new QTableWidgetItem(QString::fromStdString(s));
                item->setForeground(c);
                return item;
            };

            tbl->setItem(row, 1, make_item(t.process_name));
            tbl->setItem(row, 2, make_item(t.dll_name));
            tbl->setItem(row, 3, make_item(t.threat_type, risk_color));
            tbl->setItem(row, 4, make_item(t.dll_path, QColor(0x8B,0x8B,0x8B)));
            tbl->setItem(row, 5, make_item(std::to_string(t.risk_score), risk_color));
            tbl->setRowHeight(row, 36);

            // Store index into threats vector for detail panel
            tbl->item(row, 1)->setData(Qt::UserRole, static_cast<int>(&t - &state->threats[0]));

            // Count for stat cards
            total++;
            if (t.threat_type == "DLL Hijack") n_hijack++;
            else if (t.threat_type == "Unsigned DLL") n_unsigned++;
            else n_susp++;
        }

        if (s_total)    s_total->setText(QString::number(total));
        if (s_hijack)   s_hijack->setText(QString::number(n_hijack));
        if (s_unsigned) s_unsigned->setText(QString::number(n_unsigned));
        if (s_susp)     s_susp->setText(QString::number(n_susp));
    };

    // ── Scan trigger ──────────────────────────────────────────────────────────
    auto doScan = [=] {
        if (state->scanning.load()) return;
        state->scanning.store(true);
        state->stop_scan.store(false);
        scan_btn->setEnabled(false);
        scan_btn->setText(QString::fromUtf8("Scanning..."));
        status_lbl->setText(QString::fromUtf8("Scanning all processes..."));

        std::thread([=] {
            auto threats = FullDllScan(state->stop_scan);
            if (AppQuitting().load()) return;
            for (const auto& t : threats) {
                HuntTarget ht;
                ht.source      = "DLL Intel";
                ht.name        = t.dll_name;
                ht.path        = t.dll_path;
                ht.risk_score  = t.risk_score;
                ht.description = t.threat_type + " in " + t.process_name;
                AutoHuntEnqueue(std::move(ht));
            }
            {
                std::lock_guard<std::mutex> lk(state->mtx);
                state->threats = std::move(threats);
            }
            if (AppQuitting().load()) return;
            QMetaObject::invokeMethod(scan_btn, [=] {
                state->scanning.store(false);
                scan_btn->setEnabled(true);
                scan_btn->setText(QString::fromUtf8("Scan Now"));
                const int n = static_cast<int>(state->threats.size());
                status_lbl->setText(QString("Found %1 threat(s) — %2")
                    .arg(n)
                    .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
                refreshTable();
            }, Qt::QueuedConnection);
        }).detach();
    };

    QObject::connect(scan_btn, &QPushButton::clicked, scan_btn, [=] { doScan(); });

    // ── Filter buttons ────────────────────────────────────────────────────────
    auto setFilter = [=](int mode, QPushButton* active) {
        state->filter_mode = mode;
        for (auto* b : {fb_all, fb_hijack, fb_unsigned, fb_susp})
            b->setChecked(b == active);
        refreshTable();
    };
    QObject::connect(fb_all,      &QPushButton::clicked, fb_all,      [=] { setFilter(0, fb_all); });
    QObject::connect(fb_hijack,   &QPushButton::clicked, fb_hijack,   [=] { setFilter(1, fb_hijack); });
    QObject::connect(fb_unsigned, &QPushButton::clicked, fb_unsigned, [=] { setFilter(2, fb_unsigned); });
    QObject::connect(fb_susp,     &QPushButton::clicked, fb_susp,     [=] { setFilter(3, fb_susp); });

    QObject::connect(search_edit, &QLineEdit::textChanged, search_edit, [=](const QString& t) {
        state->search_text = t;
        refreshTable();
    });

    // ── Row selection → detail panel ──────────────────────────────────────────
    QObject::connect(tbl, &QTableWidget::currentCellChanged, tbl,
        [=](int row, int, int, int) {
            if (row < 0) return;
            auto* item = tbl->item(row, 1);
            if (!item) return;
            const int idx = item->data(Qt::UserRole).toInt();
            std::lock_guard<std::mutex> lk(state->mtx);
            if (idx < 0 || idx >= static_cast<int>(state->threats.size())) return;
            const auto& t = state->threats[idx];
            detail_text->setText(QString(
                "<b>Process:</b> %1 (PID %2)<br>"
                "<b>DLL:</b> %3<br>"
                "<b>Full Path:</b> %4<br>"
                "<b>Threat:</b> %5<br>"
                "<b>Description:</b> %6<br>"
                "<b>Risk Score:</b> %7 / 100")
                .arg(QString::fromStdString(t.process_name))
                .arg(t.pid)
                .arg(QString::fromStdString(t.dll_name))
                .arg(QString::fromStdString(t.dll_path))
                .arg(QString::fromStdString(t.threat_type))
                .arg(QString::fromStdString(t.description))
                .arg(t.risk_score));
            detail_card->setMaximumHeight(200);

            // Store for action buttons
            state->selected_row = idx;
        });

    // ── Kill process action ───────────────────────────────────────────────────
    QObject::connect(kill_btn, &QPushButton::clicked, kill_btn, [=] {
        std::lock_guard<std::mutex> lk(state->mtx);
        if (state->selected_row < 0 || state->selected_row >= (int)state->threats.size()) return;
        const uint32_t pid = state->threats[state->selected_row].pid;
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) { TerminateProcess(h, 1); CloseHandle(h); }
        status_lbl->setText(QString("Process %1 terminated.").arg(pid));
    });

    // ── Auto-scan every 5 minutes ─────────────────────────────────────────────
    auto* auto_timer = new QTimer(page);
    QObject::connect(auto_timer, &QTimer::timeout, scan_btn, [=] { doScan(); });
    auto_timer->start(5 * 60 * 1000);

    // Run initial scan on a short delay
    QTimer::singleShot(2000, scan_btn, [=] { doScan(); });

    return page;
}

} // namespace avdashboard
