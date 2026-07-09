#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTableWidgetSelectionRange>
#include <QHeaderView>
#include <QProgressBar>
#include <QLabel>
#include <QThread>
#include <QTimer>
#include <QMessageBox>

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <vector>
#include <string>
#include <memory>
#include <atomic>
#include <thread>

#include "av_quit_guard.hpp"
#include "av_animations.hpp"
#include "hunt_toolbar.hpp"

#pragma comment(lib, "psapi.lib")

namespace avdashboard {
namespace {

struct HookFinding {
    DWORD pid = 0;
    std::string proc_name;
    std::string function_name;
    std::string status; // "UNHOOKED" / "RET_IMMEDIATE" / "DETOUR_UNBACKED" / "DETOUR_MODULE"
    int risk = 0;      // 0=none, 50=medium (detour to module), 70=high (ret-immediate), 90=critical (unbacked)
    std::string note;
};

const char* kWatchedFunctions[] = {
    "AmsiScanBuffer",
    "EtwEventWrite",
    "NtQuerySystemInformation",
    "NtQueryDirectoryFile",
    "CreateRemoteThreadEx",
    "SetWindowsHookEx"
};
constexpr int kWatchedFunctionCount = sizeof(kWatchedFunctions) / sizeof(kWatchedFunctions[0]);

// Get NTDLL base address in a process
std::uintptr_t GetNtdllBase(HANDLE proc) {
    HMODULE mods[256];
    DWORD needed;
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed)) return 0;
    for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i) {
        wchar_t name[MAX_PATH];
        GetModuleBaseNameW(proc, mods[i], name, MAX_PATH);
        if (wcscmp(name, L"ntdll.dll") == 0)
            return reinterpret_cast<std::uintptr_t>(mods[i]);
    }
    return 0;
}

// Get function address from local (reference) ntdll
std::uintptr_t GetLocalFunctionAddress(const char* func_name) {
    HMODULE local_ntdll = GetModuleHandleA("ntdll.dll");
    if (!local_ntdll) return 0;
    return reinterpret_cast<std::uintptr_t>(GetProcAddress(local_ntdll, func_name));
}

// Read bytes from process memory, returns true if successful
bool ReadProcessMemory(HANDLE proc, std::uintptr_t addr, void* buf, size_t len) {
    SIZE_T read = 0;
    return ::ReadProcessMemory(proc, reinterpret_cast<LPCVOID>(addr), buf, len, &read) && read == len;
}

// Check if address is within a loaded module (returns module name if so)
std::string GetModuleAtAddress(HANDLE proc, std::uintptr_t addr) {
    HMODULE mods[256];
    DWORD needed;
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed)) return "";

    MODULEINFO info;
    for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i) {
        if (GetModuleInformation(proc, mods[i], &info, sizeof(info))) {
            auto mod_base = reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll);
            if (addr >= mod_base && addr < mod_base + info.SizeOfImage) {
                wchar_t name[MAX_PATH];
                GetModuleBaseNameW(proc, mods[i], name, MAX_PATH);
                char buf[MAX_PATH];
                wcstombs(buf, name, MAX_PATH);
                return buf;
            }
        }
    }
    return "";
}

// Analyze function prologue: detect ret-immediate, xor-eax-ret, jmp patterns
HookFinding AnalyzeFunction(HANDLE proc, DWORD pid, const char* func_name,
                            std::uintptr_t local_addr, std::uintptr_t remote_addr) {
    HookFinding result;
    result.pid = pid;
    result.function_name = func_name;
    result.status = "UNHOOKED";
    result.risk = 0;

    // Get process name
    HMODULE mod;
    if (EnumProcessModules(proc, &mod, sizeof(mod), nullptr)) {
        wchar_t name[MAX_PATH];
        GetModuleBaseNameW(proc, mod, name, MAX_PATH);
        char buf[MAX_PATH];
        wcstombs(buf, name, MAX_PATH);
        result.proc_name = buf;
    }

    unsigned char local_prologue[32] = {}, remote_prologue[32] = {};

    if (!ReadProcessMemory(proc, remote_addr, remote_prologue, 32)) {
        result.note = "Cannot read process memory";
        return result;
    }
    // Guard: local_addr could be 0 if GetProcAddress failed for a nonexistent
    // function (e.g. CreateRemoteThreadEx on older Windows). Skip if so.
    if (!local_addr) {
        result.note = "Function address could not be resolved";
        return result;
    }
    memcpy(local_prologue, reinterpret_cast<void*>(local_addr), 32);

    // Check for immediate return (0xC3 = ret, 0xC2 xx xx = ret imm16)
    if (remote_prologue[0] == 0xC3) {
        result.status = "RET_IMMEDIATE";
        result.risk = 70;
        result.note = "Function returns immediately (classic unhooking)";
        return result;
    }

    // Check for xor eax,eax; ret (0x33 0xC0 0xC3)
    if (remote_prologue[0] == 0x33 && remote_prologue[1] == 0xC0 && remote_prologue[2] == 0xC3) {
        result.status = "RET_IMMEDIATE";
        result.risk = 70;
        result.note = "XOR EAX,EAX; RET pattern (immediate return 0)";
        return result;
    }

    // Check for jmp (0xE9 = jmp rel32, 0xFF 0x25 = jmp [rip+rel32], 0xEB = jmp rel8)
    if (remote_prologue[0] == 0xE9 || remote_prologue[0] == 0xEB) {
        // Extract jmp target (simplified: assume near relative jmp)
        // For 0xE9: offset is at [1..4], target = pc+5+offset
        if (remote_prologue[0] == 0xE9) {
            std::int32_t rel_offset = *reinterpret_cast<std::int32_t*>(&remote_prologue[1]);
            std::uintptr_t target = remote_addr + 5 + rel_offset;
            std::string target_module = GetModuleAtAddress(proc, target);

            if (target_module.empty()) {
                result.status = "DETOUR_UNBACKED";
                result.risk = 90;
                result.note = "JMP to unbacked memory (detour to attacker code)";
            } else {
                result.status = "DETOUR_MODULE";
                result.risk = 50;
                result.note = "JMP to module: " + target_module + " (could be legit AV)";
            }
            return result;
        }
    }

    // Check for indirect jmp via memory (0xFF 0x25 on x64)
    if (remote_prologue[0] == 0xFF && remote_prologue[1] == 0x25) {
        result.status = "DETOUR_MODULE"; // Being conservative; indirect jumps often go through imports
        result.risk = 50;
        result.note = "Indirect JMP via memory (possible hook/detour)";
        return result;
    }

    // Compare prologue bytes (if not hooked, should match local)
    bool differs = false;
    for (int i = 0; i < 16; ++i) {
        if (local_prologue[i] != remote_prologue[i]) {
            differs = true;
            break;
        }
    }
    if (differs && remote_prologue[0] != 0xC3 && remote_prologue[0] != 0xE9 && remote_prologue[0] != 0xEB) {
        result.status = "MODIFIED";
        result.risk = 50;
        result.note = "Prologue differs from reference (possible hook)";
        return result;
    }

    return result;
}

std::vector<HookFinding> ScanForHooks(std::atomic<bool>& cancel) {
    std::vector<HookFinding> out;

    DWORD pids[2048];
    DWORD needed;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) return out;

    int count = needed / sizeof(DWORD);
    for (int i = 0; i < count; ++i) {
        if (cancel.load()) break;

        DWORD pid = pids[i];
        if (pid == 0) continue;

        HANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!proc) continue;

        std::uintptr_t remote_ntdll = GetNtdllBase(proc);
        if (!remote_ntdll) {
            CloseHandle(proc);
            continue;
        }

        for (int j = 0; j < kWatchedFunctionCount; ++j) {
            if (cancel.load()) break;

            const char* func = kWatchedFunctions[j];
            std::uintptr_t local_addr = GetLocalFunctionAddress(func);
            if (!local_addr) continue;

            std::uintptr_t remote_addr = remote_ntdll + (local_addr - reinterpret_cast<std::uintptr_t>(GetModuleHandleA("ntdll.dll")));

            HookFinding finding = AnalyzeFunction(proc, pid, func, local_addr, remote_addr);
            if (finding.risk > 0) {
                out.push_back(finding);
            }
        }

        CloseHandle(proc);
    }

    return out;
}

} // anonymous namespace

QWidget* BuildHookHuntPage(QWidget* parent) {
    QWidget* page = new QWidget(parent);
    QVBoxLayout* layout = new QVBoxLayout(page);

    QLabel* info = new QLabel(
        "Hook Integrity Hunt: Detects AMSI/ETW unhooking (malware patching AmsiScanBuffer, "
        "EtwEventWrite, and other critical functions to blind AV/EDR). "
        "Risk levels: 90=detour to unbacked memory (critical injection), "
        "70=immediate return (high EDR evasion), 50=detour to module (medium, could be legit AV).");
    info->setWordWrap(true);
    layout->addWidget(info);

    QTableWidget* table = new QTableWidget();
    table->setColumnCount(6);
    table->setHorizontalHeaderLabels({"Process", "PID", "Function", "Status", "Risk", "Note"});
    table->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(table);

    QProgressBar* progress = new QProgressBar();
    progress->setVisible(false);
    layout->addWidget(progress);

    QLabel* status_label = new QLabel("");
    status_label->setStyleSheet("color:#8B8B8B; font-size:11px;");
    status_label->setVisible(false);
    layout->addWidget(status_label);

    QHBoxLayout* btn_layout = new QHBoxLayout();
    QPushButton* scan_btn = new QPushButton("Scan for Hooked Functions");
    auto* stop_btn = new QPushButton(QString::fromUtf8("Stop"));
    stop_btn->setEnabled(false);
    QPushButton* kill_btn = new QPushButton("Kill Selected Process");
    kill_btn->setEnabled(false);
    btn_layout->addWidget(scan_btn);
    btn_layout->addWidget(stop_btn);
    btn_layout->addWidget(kill_btn);
    // Clean + Export via the shared hunt toolbar helper.
    auto* clean_btn  = MakeCleanButton(page, table);
    auto* export_btn = MakeExportButton(page, table,
                                        QString::fromUtf8("hook_findings.csv"));
    btn_layout->addWidget(clean_btn);
    btn_layout->addWidget(export_btn);
    layout->addLayout(btn_layout);

    // Scan thread
    avdashboard::ArmQuitGuard(page);

    // Page-scoped so the Stop button and the detached worker share one flag.
    // (Previously `cancel` was a local inside this handler captured by
    // reference into a detached thread -- a dangling reference the moment the
    // handler returned. Promoting it to a shared_ptr fixes that too.)
    auto cancel   = std::make_shared<std::atomic<bool>>(false);
    auto scanning = std::make_shared<std::atomic<bool>>(false);

    QObject::connect(scan_btn, &QPushButton::clicked, [=]() {
        if (scanning->load()) return;
        table->setRowCount(0);
        progress->setVisible(true);
        progress->setValue(0);
        status_label->setText("Scanning processes...");
        status_label->setVisible(true);
        scan_btn->setEnabled(false);
        kill_btn->setEnabled(false);

        cancel->store(false);
        scanning->store(true);

        std::thread scan_thread([=]() {
            std::vector<HookFinding> findings = ScanForHooks(*cancel);
            scanning->store(false);

            if (!cancel->load()) {
                QMetaObject::invokeMethod(table, [table, findings, status_label]() {
                    table->setRowCount(static_cast<int>(findings.size()));

                    // Color-code rows by risk level
                    for (size_t i = 0; i < findings.size(); ++i) {
                        const auto& f = findings[i];
                        auto* proc_item = new QTableWidgetItem(f.proc_name.c_str());
                        auto* pid_item = new QTableWidgetItem(QString::number(f.pid));
                        auto* func_item = new QTableWidgetItem(f.function_name.c_str());
                        auto* status_item = new QTableWidgetItem(f.status.c_str());
                        auto* risk_item = new QTableWidgetItem(QString::number(f.risk));
                        auto* note_item = new QTableWidgetItem(f.note.c_str());

                        // Color-code by risk
                        QString bg_color;
                        if (f.risk >= 90) bg_color = "#3A1F1F"; // critical red
                        else if (f.risk >= 70) bg_color = "#3A2F1F"; // high orange
                        else if (f.risk >= 50) bg_color = "#2F3A1F"; // medium yellow
                        else bg_color = "#1F2F1F"; // low green

                        for (auto* item : {proc_item, pid_item, func_item, status_item, risk_item, note_item}) {
                            item->setBackground(QColor(bg_color));
                        }

                        table->setItem(static_cast<int>(i), 0, proc_item);
                        table->setItem(static_cast<int>(i), 1, pid_item);
                        table->setItem(static_cast<int>(i), 2, func_item);
                        table->setItem(static_cast<int>(i), 3, status_item);
                        table->setItem(static_cast<int>(i), 4, risk_item);
                        table->setItem(static_cast<int>(i), 5, note_item);
                    }

                    if (findings.empty()) {
                        status_label->setText("No hooked functions detected");
                    } else {
                        status_label->setText(QString("Found %1 hooked function(s)").arg(findings.size()));
                    }
                });
            }

            if (!cancel->load()) {
                QMetaObject::invokeMethod(progress, [progress]() { progress->setVisible(false); });
                QMetaObject::invokeMethod(scan_btn, [scan_btn]() { scan_btn->setEnabled(true); });
                QMetaObject::invokeMethod(kill_btn, [kill_btn]() { kill_btn->setEnabled(true); });
            } else {
                QMetaObject::invokeMethod(progress, [progress]() { progress->setVisible(false); });
                QMetaObject::invokeMethod(scan_btn, [scan_btn]() { scan_btn->setEnabled(true); });
            }
        });
        scan_thread.detach();
    });

    // Stop: signal the shared cancel flag; the worker checks it between processes.
    QObject::connect(stop_btn, &QPushButton::clicked, page,
                     [stop_btn, status_label, cancel, scanning]() {
        if (!scanning->load()) return;
        cancel->store(true);
        stop_btn->setEnabled(false);
        status_label->setVisible(true);
        status_label->setText(QString::fromUtf8("Stopping..."));
    });

    // Keep Stop/Clean/Export in sync with scan + result state.
    auto* sync = new QTimer(page);
    sync->setInterval(300);
    QObject::connect(sync, &QTimer::timeout, stop_btn,
                     [stop_btn, clean_btn, export_btn, table, scanning]() {
        const bool busy = scanning->load();
        const bool has_rows = table->rowCount() > 0;
        stop_btn->setEnabled(busy);
        clean_btn->setEnabled(!busy && has_rows);
        export_btn->setEnabled(!busy && has_rows);
    });
    sync->start();

    // Kill process
    QObject::connect(kill_btn, &QPushButton::clicked, [table, page]() {
        int row = table->currentRow();
        if (row < 0) {
            QMessageBox::warning(page, "No Selection", "Select a process row first.");
            return;
        }

        bool ok;
        DWORD pid = table->item(row, 1)->text().toULong(&ok);
        if (!ok) return;

        QString msg = QString("Kill PID %1?\n\nWarning: This process may be critical to the system. "
                             "Killing it could destabilize Windows.").arg(pid);
        if (QMessageBox::warning(page, "Confirm Kill", msg, QMessageBox::Ok, QMessageBox::Cancel) != QMessageBox::Ok)
            return;

        HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (proc) {
            TerminateProcess(proc, 1);
            CloseHandle(proc);
            QMessageBox::information(page, "Done", "Process terminated.");
            table->removeRow(row);
        } else {
            QMessageBox::warning(page, "Error", "Could not open process.");
        }
    });

    return page;
}

} // namespace avdashboard
