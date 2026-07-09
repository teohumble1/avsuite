// main_window_memhunt.cpp — Memory Injection Hunt.
//
// APTs and modern malware increasingly avoid writing anything to disk at
// all: they inject shellcode or a reflectively-loaded DLL directly into a
// legitimate process's memory (process hollowing, reflective DLL injection,
// classic CreateRemoteThread+shellcode) and run entirely in RAM. The
// existing Memory Scan (Engine::ScanAllProcesses) already reads private
// executable memory pages, but only flags a YARA *signature* match --
// a novel/unknown implant with no matching rule sails through untouched.
//
// This page adds the complementary STRUCTURAL heuristic real EDR tools use
// (PE-sieve, Moneta, Hollows Hunter follow the same idea): a committed,
// PRIVATE, executable memory region has no backing file on disk by
// definition -- legitimate code lives in MEM_IMAGE regions backed by the
// module's on-disk PE. Finding one is suspicious regardless of content.
// Correlating it with a thread whose start address falls inside that same
// region (via the undocumented-but-stable NtQueryInformationThread /
// ThreadQuerySetWin32StartAddress, the same technique Sysinternals/Process
// Hacker use) turns "theoretically executable" into "actually running",
// cutting most of the false-positive noise from legitimate JIT engines.
//
// Honesty note: this is a heuristic, not a verdict. Some legitimate
// software (JIT compilers, script engines, some DRM/anti-cheat) also
// allocates unbacked executable memory. Pair a finding here with the
// existing signature-based Memory Scan or manual review before acting;
// "Kill Process" is offered but gated behind a confirmation dialog.
//
// ASCII labels (MSVC builds without /utf-8).

#include "main_window.hpp"
#include "av_quit_guard.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QFileDialog>
#include <QFile>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#pragma comment(lib, "psapi.lib")

#include <algorithm>
#include <atomic>
#include <cctype>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace avdashboard {
namespace {

struct MemFinding {
    std::string proc_name;
    DWORD       pid = 0;
    std::uintptr_t region_addr = 0;
    SIZE_T      region_size = 0;
    int         threads_here = 0;
    int         risk = 0;
    std::string note;
};

// Same noise-reduction rationale as Engine::ScanProcessMemoryImpl: these
// processes legitimately allocate unbacked executable memory (JIT, script
// hosts) often enough that scanning them here is mostly false positives.
const std::unordered_set<std::string>& SkipList() {
    static const std::unordered_set<std::string> kSkip = {
        "system", "registry", "memory compression", "idle",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsm.exe",
        "svchost.exe", "dwm.exe", "fontdrvhost.exe",
        "sihost.exe", "taskhostw.exe", "runtimebroker.exe",
        "ctfmon.exe", "conhost.exe", "dllhost.exe",
        "spoolsv.exe", "audiodg.exe", "dashost.exe",
        "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
        "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
        "securityhealthsystray.exe", "wuauclt.exe", "wermgr.exe",
        "msiexec.exe", "wlanext.exe",
    };
    return kSkip;
}

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

// NtQueryInformationThread(..., ThreadQuerySetWin32StartAddress=9, ...) is
// undocumented but has been ABI-stable since XP; Sysinternals Process
// Explorer/Hacker rely on the same call. Resolved once, lazily, via
// GetProcAddress -- if it's ever unavailable, thread correlation is simply
// skipped (region-only heuristic still works).
using NtQueryInformationThreadFn =
    LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

NtQueryInformationThreadFn ResolveNtQueryInformationThread() {
    static const NtQueryInformationThreadFn fn = reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    return fn;
}

// Every thread's Win32 start address in this process, best-effort.
std::vector<std::uintptr_t> ThreadStartAddresses(DWORD pid) {
    std::vector<std::uintptr_t> out;
    const auto NtQIT = ResolveNtQueryInformationThread();
    if (!NtQIT) return out;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            // THREAD_QUERY_LIMITED_INFORMATION is documented as sufficient for
            // ThreadQuerySetWin32StartAddress, but empirically (verified with a
            // standalone harness against a live process) NtQueryInformationThread
            // returns STATUS_ACCESS_DENIED (0xC0000022) for every thread with
            // just the limited right on at least some configurations. Full
            // THREAD_QUERY_INFORMATION is needed for this call to actually work.
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!th) continue;
            PVOID start_addr = nullptr;
            constexpr ULONG kThreadQuerySetWin32StartAddress = 9;
            if (NtQIT(th, kThreadQuerySetWin32StartAddress, &start_addr, sizeof(start_addr), nullptr) == 0) {
                out.push_back(reinterpret_cast<std::uintptr_t>(start_addr));
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return out;
}

std::vector<MemFinding> ScanForInjection(std::atomic<bool>& cancel) {
    std::vector<MemFinding> out;

    DWORD pids[2048] = {};
    DWORD needed = 0;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) return out;
    const DWORD count = needed / sizeof(DWORD);

    static constexpr DWORD kExecMask =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    static constexpr SIZE_T kMaxRegion = 64ull * 1024 * 1024;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    for (DWORD i = 0; i < count && !cancel.load(); ++i) {
        const DWORD pid = pids[i];
        if (pid == 0) continue;
        HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!h) continue;

        wchar_t img[MAX_PATH] = {};
        GetProcessImageFileNameW(h, img, MAX_PATH);
        std::wstring ws(img);
        const auto slash = ws.rfind(L'\\');
        std::string name;
        {
            std::wstring wname = (slash != std::wstring::npos) ? ws.substr(slash + 1) : ws;
            name.assign(wname.begin(), wname.end()); // exe names are ASCII in practice
        }
        if (name.empty() || SkipList().count(ToLower(name))) { CloseHandle(h); continue; }

        std::vector<std::uintptr_t> thread_starts; // resolved lazily, only if a region is found
        bool starts_loaded = false;

        MEMORY_BASIC_INFORMATION mbi{};
        auto* addr = static_cast<const char*>(si.lpMinimumApplicationAddress);
        const auto* end = static_cast<const char*>(si.lpMaximumApplicationAddress);
        while (addr < end) {
            if (cancel.load()) break;
            if (!VirtualQueryEx(h, addr, &mbi, sizeof(mbi))) break;

            const bool suspicious =
                mbi.State == MEM_COMMIT
                && mbi.Type == MEM_PRIVATE
                && mbi.RegionSize >= 4096
                && mbi.RegionSize <= kMaxRegion
                && !(mbi.Protect & PAGE_GUARD)
                && !(mbi.Protect & PAGE_NOACCESS)
                && (mbi.Protect & kExecMask);

            if (suspicious) {
                if (!starts_loaded) {
                    thread_starts = ThreadStartAddresses(pid);
                    starts_loaded = true;
                }
                const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const auto top = base + mbi.RegionSize;
                int threads_here = 0;
                for (auto ts : thread_starts)
                    if (ts >= base && ts < top) ++threads_here;

                MemFinding f;
                f.proc_name = name;
                f.pid = pid;
                f.region_addr = base;
                f.region_size = mbi.RegionSize;
                f.threads_here = threads_here;
                if (threads_here > 0) {
                    f.risk = 90;
                    f.note = "Unbacked executable memory with a thread running inside it "
                             "-- strong process-injection indicator";
                } else {
                    f.risk = 55;
                    f.note = "Unbacked executable memory, no active thread found there "
                             "-- review (could be JIT, or injection between snapshot steps)";
                }
                out.push_back(std::move(f));
            }
            // Guard against a zero-size region: VirtualQueryEx normally returns a
            // non-zero RegionSize, but if it ever came back 0 the pointer would
            // never advance and this per-process walk would spin forever, hanging
            // the scan thread. Bail out of this process's walk instead.
            if (mbi.RegionSize == 0) break;
            addr += mbi.RegionSize;
        }
        CloseHandle(h);
    }
    return out;
}

QColor RiskColor(int r) {
    if (r >= 70) return QColor(0xFF, 0x3B, 0x50);
    if (r >= 10) return QColor(0xE6, 0xC2, 0x4A);
    return QColor(0x4A, 0xDE, 0x80);
}

} // namespace

QWidget* BuildMemHuntPage(QWidget* parent) {
    (void)parent;
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(12);

    auto* title = new QLabel(QString::fromUtf8("Memory Injection Hunt"), page);
    title->setStyleSheet("color:#FFFFFF; font-size:16pt; font-weight:800; background:transparent;");
    root->addWidget(title);
    auto* sub = new QLabel(QString::fromUtf8(
        "Finds fileless/injected code: executable memory with no backing file on disk "
        "(process hollowing, reflective DLL injection, shellcode), cross-referenced against "
        "which threads are actually running there. Heuristic, not a verdict -- some legitimate "
        "JIT/script engines also trip this. Complements Memory Scan's YARA-signature pass, "
        "which only catches known patterns."), page);
    sub->setStyleSheet("color:#8B7355; font-size:9pt; background:transparent;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(12);
    auto* scan_btn = new QPushButton(QString::fromUtf8("Scan running processes"), page);
    scan_btn->setCursor(Qt::PointingHandCursor);
    scan_btn->setStyleSheet(
        "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #CC5500);"
        " border:none; border-radius:10px; color:#fff; font-size:10.5pt; font-weight:700; padding:10px 24px; }"
        "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9030,stop:1 #DD6600); }"
        "QPushButton:disabled { background:#3A2A1C; color:#8B7355; }");
    ctl->addWidget(scan_btn);

    // Stop: cancels an in-progress scan (the worker already honours the
    // `cancel` atomic; this just exposes it in the UI). Disabled unless a scan
    // is actually running.
    auto* stop_btn = new QPushButton(QString::fromUtf8("Stop"), page);
    stop_btn->setCursor(Qt::PointingHandCursor);
    stop_btn->setEnabled(false);
    stop_btn->setStyleSheet(
        "QPushButton { background:#2A2010; border:1px solid #E6C24A; border-radius:10px;"
        " color:#E6C24A; font-size:10pt; font-weight:700; padding:10px 20px; }"
        "QPushButton:hover { background:#3A2C14; }"
        "QPushButton:disabled { background:#241814; color:#6B5444; border-color:#3A2A1C; }");
    ctl->addWidget(stop_btn);

    auto* kill_btn = new QPushButton(QString::fromUtf8("Kill selected process"), page);
    kill_btn->setCursor(Qt::PointingHandCursor);
    kill_btn->setEnabled(false);
    kill_btn->setStyleSheet(
        "QPushButton { background:#3A1414; border:1px solid #FF5A6A; border-radius:10px;"
        " color:#FF5A6A; font-size:10pt; font-weight:700; padding:10px 20px; }"
        "QPushButton:hover { background:#4A1818; }"
        "QPushButton:disabled { background:#241814; color:#6B5444; border-color:#3A2A1C; }");
    ctl->addWidget(kill_btn);

    // Clean: clears the results table so the next scan starts fresh.
    auto* clean_btn = new QPushButton(QString::fromUtf8("Clean"), page);
    clean_btn->setCursor(Qt::PointingHandCursor);
    clean_btn->setEnabled(false);
    clean_btn->setStyleSheet(
        "QPushButton { background:#241814; border:1px solid rgba(255,170,90,60); border-radius:10px;"
        " color:#C7B6A2; font-size:10pt; font-weight:700; padding:10px 20px; }"
        "QPushButton:hover { background:#2F2016; }"
        "QPushButton:disabled { background:#241814; color:#6B5444; border-color:#3A2A1C; }");
    ctl->addWidget(clean_btn);

    // Export: writes the current findings to a CSV file for reporting.
    auto* export_btn = new QPushButton(QString::fromUtf8("Export"), page);
    export_btn->setCursor(Qt::PointingHandCursor);
    export_btn->setEnabled(false);
    export_btn->setStyleSheet(
        "QPushButton { background:#152A1A; border:1px solid #4ADE80; border-radius:10px;"
        " color:#4ADE80; font-size:10pt; font-weight:700; padding:10px 20px; }"
        "QPushButton:hover { background:#1A331F; }"
        "QPushButton:disabled { background:#241814; color:#6B5444; border-color:#3A2A1C; }");
    ctl->addWidget(export_btn);

    auto* status = new QLabel(QString::fromUtf8("Idle."), page);
    status->setStyleSheet("color:#C7B6A2; font-size:9.5pt; background:transparent;");
    ctl->addWidget(status, 1);
    root->addLayout(ctl);

    auto* table = new QTableWidget(0, 6, page);
    table->setHorizontalHeaderLabels({"Process", "PID", "Region", "Size", "Threads Here", "Note"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);
    table->setStyleSheet(
        "QTableWidget { background:#1A120C; color:#E8D5C0; font-size:9.5pt; border:1px solid rgba(255,170,90,26);"
        " border-radius:10px; gridline-color:#2A1F14; }"
        "QTableWidget::item { padding:5px 8px; }"
        "QHeaderView::section { background:#130D07; color:#8B7355; font-size:9pt; font-weight:700;"
        " padding:6px; border:none; border-bottom:1px solid #2A1F14; }");
    {
        auto* h = table->horizontalHeader();
        h->setStretchLastSection(true);
        h->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    }
    root->addWidget(table, 1);

    ArmQuitGuard(page);
    auto scanning = std::make_shared<std::atomic<bool>>(false);
    auto cancel = std::make_shared<std::atomic<bool>>(false);

    QObject::connect(table, &QTableWidget::itemSelectionChanged, table, [table, kill_btn] {
        kill_btn->setEnabled(!table->selectionModel()->selectedRows().isEmpty());
    });

    QObject::connect(kill_btn, &QPushButton::clicked, page, [page, table] {
        const auto rows = table->selectionModel()->selectedRows();
        if (rows.isEmpty()) return;
        const int row = rows.first().row();
        const auto* pid_item = table->item(row, 1);
        const auto* name_item = table->item(row, 0);
        if (!pid_item) return;
        const DWORD pid = pid_item->text().toULong();
        const auto reply = QMessageBox::question(page, QString::fromUtf8("Confirm kill"),
            QString::fromUtf8("Terminate %1 (PID %2)? This heuristic can false-positive on "
                               "legitimate JIT/script engines -- make sure you recognize this "
                               "process before killing it.")
                .arg(name_item ? name_item->text() : QString("?")).arg(pid),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (reply != QMessageBox::Yes) return;
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) { TerminateProcess(h, 1); CloseHandle(h); }
    });

    // Stop: signal the worker to bail out of its process/memory walk.
    QObject::connect(stop_btn, &QPushButton::clicked, page, [stop_btn, status, cancel, scanning] {
        if (!scanning->load()) return;
        cancel->store(true);
        stop_btn->setEnabled(false);
        status->setText(QString::fromUtf8("Stopping..."));
    });

    // Clean: wipe the results table (disabled mid-scan to avoid racing rows).
    QObject::connect(clean_btn, &QPushButton::clicked, page,
                     [table, status, clean_btn, export_btn, scanning] {
        if (scanning->load()) return;
        table->setRowCount(0);
        status->setText(QString::fromUtf8("Idle."));
        clean_btn->setEnabled(false);
        export_btn->setEnabled(false);
    });

    // Export: dump the current table to CSV via a save dialog.
    QObject::connect(export_btn, &QPushButton::clicked, page, [page, table, status] {
        if (table->rowCount() == 0) return;
        const QString fn = QFileDialog::getSaveFileName(
            page, QString::fromUtf8("Export findings"),
            QString::fromUtf8("memory_injection_findings.csv"),
            QString::fromUtf8("CSV files (*.csv);;All files (*.*)"));
        if (fn.isEmpty()) return;
        QFile out(fn);
        if (!out.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(page, QString::fromUtf8("Export failed"),
                QString::fromUtf8("Could not open the file for writing."));
            return;
        }
        QTextStream ts(&out);
        const int cols = table->columnCount();
        // Header row from the table's own labels.
        QStringList headers;
        for (int c = 0; c < cols; ++c)
            headers << table->horizontalHeaderItem(c)->text();
        ts << headers.join(',') << '\n';
        // CSV-escape any field containing a comma or quote.
        auto esc = [](QString v) -> QString {
            if (v.contains(',') || v.contains('"') || v.contains('\n')) {
                v.replace('"', "\"\"");
                return '"' + v + '"';
            }
            return v;
        };
        for (int r = 0; r < table->rowCount(); ++r) {
            QStringList row;
            for (int c = 0; c < cols; ++c) {
                const auto* it = table->item(r, c);
                row << esc(it ? it->text() : QString());
            }
            ts << row.join(',') << '\n';
        }
        out.close();
        status->setText(QString::fromUtf8("Exported %1 finding(s) to %2")
                            .arg(table->rowCount()).arg(fn));
    });

    auto refresh = [page, scan_btn, stop_btn, clean_btn, export_btn, status, table, scanning, cancel] {
        if (scanning->load()) return;
        scanning->store(true);
        cancel->store(false);
        scan_btn->setEnabled(false);
        stop_btn->setEnabled(true);
        clean_btn->setEnabled(false);
        export_btn->setEnabled(false);
        table->setRowCount(0);
        status->setText(QString::fromUtf8("Scanning process memory..."));
        std::thread([status, table, scanning, cancel] {
            auto findings = ScanForInjection(*cancel);
            if (AppQuitting().load()) { scanning->store(false); return; }

            std::sort(findings.begin(), findings.end(),
                      [](const MemFinding& a, const MemFinding& b) { return a.risk > b.risk; });
            const int flagged_high = static_cast<int>(std::count_if(
                findings.begin(), findings.end(), [](const MemFinding& f) { return f.risk >= 70; }));
            const int total = static_cast<int>(findings.size());

            QMetaObject::invokeMethod(table, [table, findings] {
                for (const auto& f : findings) {
                    const int row = table->rowCount();
                    table->insertRow(row);
                    QString bg; if (f.risk >= 90) bg = "#3A1F1F"; else if (f.risk >= 70) bg = "#3A2F1F"; else if (f.risk >= 50) bg = "#2F3A1F"; else bg = "#1F2F1F";
                    auto* proc = new QTableWidgetItem(QString::fromStdString(f.proc_name)); proc->setBackground(QColor(bg)); table->setItem(row, 0, proc);
                    auto* pid = new QTableWidgetItem(QString::number(f.pid)); pid->setBackground(QColor(bg)); table->setItem(row, 1, pid);
                    std::ostringstream addr_hex; addr_hex << "0x" << std::hex << f.region_addr;
                    auto* addr = new QTableWidgetItem(QString::fromStdString(addr_hex.str())); addr->setBackground(QColor(bg)); table->setItem(row, 2, addr);
                    auto* size = new QTableWidgetItem(QString::number(f.region_size / 1024) + " KB"); size->setBackground(QColor(bg)); table->setItem(row, 3, size);
                    auto* threads = new QTableWidgetItem(QString::number(f.threads_here)); threads->setBackground(QColor(bg)); table->setItem(row, 4, threads);
                    auto* note = new QTableWidgetItem(QString::fromStdString(f.note)); note->setForeground(RiskColor(f.risk)); note->setBackground(QColor(bg)); table->setItem(row, 5, note);
                }
            }, Qt::QueuedConnection);
            const bool was_cancelled = cancel->load();
            QMetaObject::invokeMethod(status, [status, total, flagged_high, was_cancelled] {
                if (was_cancelled) {
                    status->setText(QString::fromUtf8("Stopped. %1 region(s) flagged so far, "
                                                       "%2 high-confidence.")
                                         .arg(total).arg(flagged_high));
                } else {
                    status->setText(QString::fromUtf8("Done. %1 region(s) flagged, "
                                                       "%2 high-confidence.")
                                         .arg(total).arg(flagged_high));
                }
            }, Qt::QueuedConnection);
            scanning->store(false);
        }).detach();
    };

    QObject::connect(scan_btn, &QPushButton::clicked, page, refresh);

    // Keep button states in sync with scan/result state without threading them
    // through every callback: scan runs -> Scan off / Stop on; idle with rows
    // -> Clean + Export on.
    auto* sync = new QTimer(page);
    sync->setInterval(300);
    QObject::connect(sync, &QTimer::timeout, scan_btn,
                     [scan_btn, stop_btn, clean_btn, export_btn, table, scanning] {
        const bool busy = scanning->load();
        const bool has_rows = table->rowCount() > 0;
        scan_btn->setEnabled(!busy);
        stop_btn->setEnabled(busy);
        clean_btn->setEnabled(!busy && has_rows);
        export_btn->setEnabled(!busy && has_rows);
    });
    sync->start();
    // Deliberately NOT auto-run on page construction: this is a full-system
    // process/memory walk (heavier than LAN Monitor's ARP read), so it only
    // runs when the user explicitly asks for it.

    return page;
}

} // namespace avdashboard
