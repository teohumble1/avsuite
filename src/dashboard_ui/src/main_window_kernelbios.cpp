// main_window_kernelbios.cpp — Kernel/BIOS scan page.
//
// Two independent checks that sit below normal file/process scanning:
//   * Loaded kernel drivers (EnumDeviceDrivers) checked against Authenticode
//     (embedded + catalog) signatures via avpe::IsAuthenticodeSigned -- an
//     unsigned kernel driver is a strong rootkit/BYOVD indicator.
//   * Firmware identity: BIOS vendor/version/release date + system
//     manufacturer/product/serial/UUID parsed from the raw SMBIOS table
//     (GetSystemFirmwareTable 'RSMB'), plus UEFI Secure Boot state from the
//     registry. Read-only, informational -- no "this BIOS is evil" heuristic
//     is attempted since there's no reliable signal for that from usermode.
//
// ASCII labels (MSVC builds without /utf-8).

#include "main_window.hpp"
#include "theme.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QCoreApplication>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "avpe/authenticode.hpp"

namespace avdashboard {
namespace {

// ── Kernel driver enumeration ────────────────────────────────────────────

struct DriverInfo {
    QString name;
    QString path;
    QString base_addr;
    bool    is_signed = false;
    QString note;
    int     risk = 0;
};

std::string NarrowUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, out.data(), len, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

// NT device-form driver paths (e.g. "\Device\HarddiskVolume3\Windows\...")
// aren't directly openable by Win32 CreateFile-based APIs -- the GLOBALROOT
// prefix trick makes them so. Some drivers instead report a "\SystemRoot\"
// relative path, which just needs the real Windows directory substituted in.
std::wstring ResolveOpenablePath(const std::wstring& dev_path) {
    if (dev_path.empty()) return dev_path;
    if (dev_path.rfind(L"\\SystemRoot\\", 0) == 0) {
        wchar_t win_dir[MAX_PATH] = {};
        GetWindowsDirectoryW(win_dir, MAX_PATH);
        return std::wstring(win_dir) + dev_path.substr(11); // keep the leading '\' after SystemRoot
    }
    if (dev_path[0] == L'\\' && dev_path.rfind(L"\\\\?\\", 0) != 0) {
        return L"\\\\?\\GLOBALROOT" + dev_path;
    }
    return dev_path;
}

// Can we even open this file to read it? A signature check that returns
// "not signed" is meaningless if the file couldn't be opened in the first
// place (protected/locked driver, or a path this tool failed to resolve).
// Distinguishing the two is what keeps a legitimate but unreadable driver
// (e.g. an EDR/anti-cheat self-protecting its own .sys) from being screamed
// at as a rootkit.
bool CanOpenForRead(const std::wstring& wpath) {
    if (wpath.empty()) return false;
    const HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

std::vector<DriverInfo> EnumerateDrivers() {
    std::vector<DriverInfo> out;
    std::vector<LPVOID> bases(1024);
    DWORD needed = 0;
    if (!EnumDeviceDrivers(bases.data(), static_cast<DWORD>(bases.size() * sizeof(LPVOID)), &needed))
        return out;
    size_t count = needed / sizeof(LPVOID);
    if (count > bases.size()) {
        bases.resize(count);
        if (!EnumDeviceDrivers(bases.data(), static_cast<DWORD>(bases.size() * sizeof(LPVOID)), &needed))
            return out;
        count = needed / sizeof(LPVOID);
    }
    bases.resize(count);

    for (auto base : bases) {
        wchar_t name_buf[MAX_PATH] = {};
        wchar_t path_buf[MAX_PATH] = {};
        GetDeviceDriverBaseNameW(base, name_buf, MAX_PATH);
        GetDeviceDriverFileNameW(base, path_buf, MAX_PATH);

        DriverInfo d;
        d.name = QString::fromWCharArray(name_buf);
        d.path = QString::fromWCharArray(path_buf);
        char addr_buf[32];
        std::snprintf(addr_buf, sizeof(addr_buf), "0x%016llX",
                      static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(base)));
        d.base_addr = QString::fromLatin1(addr_buf);
        if (!d.name.isEmpty()) out.push_back(std::move(d));
    }
    return out;
}

QColor RiskColor(int r) {
    if (r >= 70) return QColor(0xFF, 0x3B, 0x50);
    if (r >= 10) return QColor(0xE6, 0xC2, 0x4A);
    return QColor(0x4A, 0xDE, 0x80);
}

// The kernel service name is, by overwhelming convention, the driver file's
// base name without the ".sys" extension (e.g. "beep.sys" -> service "beep").
// Not guaranteed -- if a driver registered its service under a different name,
// sc will just report "service does not exist", which the caller surfaces.
QString ServiceNameFromDriver(const QString& driver_name) {
    QString n = driver_name;
    if (n.endsWith(".sys", Qt::CaseInsensitive)) n.chop(4);
    return n;
}

// Runs sc.exe <args> synchronously, returns {exitCode, combinedOutput}.
// exitCode -1 means the process failed to start. sc needs Administrator; when
// the app isn't elevated the output carries "Access is denied" (Win err 5),
// which the caller turns into a clear "run as Administrator" message.
struct ScResult { int code; QString output; };
ScResult RunSc(const QStringList& args) {
    QProcess p;
    p.start("sc.exe", args);
    if (!p.waitForStarted(4000)) return {-1, "Could not launch sc.exe"};
    p.waitForFinished(15000);
    QString out = QString::fromLocal8Bit(p.readAllStandardOutput())
                + QString::fromLocal8Bit(p.readAllStandardError());
    return {p.exitCode(), out.trimmed()};
}

bool ScLooksLikeAccessDenied(const ScResult& r) {
    return r.output.contains("Access is denied", Qt::CaseInsensitive)
        || r.output.contains("OpenSCManager FAILED 5", Qt::CaseInsensitive)
        || r.output.contains("FAILED 5", Qt::CaseInsensitive);
}

// ── SMBIOS / firmware ────────────────────────────────────────────────────

#pragma pack(push, 1)
struct RawSMBIOSData {
    BYTE  Used20CallingMethod;
    BYTE  SMBIOSMajorVersion;
    BYTE  SMBIOSMinorVersion;
    BYTE  DmiRevision;
    DWORD Length;
    BYTE  SMBIOSTableData[1];
};
#pragma pack(pop)

QString SmbiosString(const BYTE* struct_start, BYTE struct_len, BYTE index) {
    if (index == 0) return QString();
    const char* p = reinterpret_cast<const char*>(struct_start + struct_len);
    BYTE cur = 1;
    while (*p) {
        if (cur == index) return QString::fromLatin1(p);
        p += std::strlen(p) + 1;
        ++cur;
    }
    return QString();
}

struct BiosInfo {
    bool    ok = false;
    QString vendor, version, release_date;
    QString sys_manufacturer, sys_product, sys_serial, sys_uuid;
    bool    secure_boot_known = false;
    bool    secure_boot_enabled = false;
};

BiosInfo ReadBiosInfo() {
    BiosInfo info;
    const DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size == 0) return info;
    std::vector<BYTE> buf(size);
    if (GetSystemFirmwareTable('RSMB', 0, buf.data(), size) != size) return info;

    auto* raw = reinterpret_cast<RawSMBIOSData*>(buf.data());
    const BYTE* p = raw->SMBIOSTableData;
    const BYTE* end = raw->SMBIOSTableData + raw->Length;
    bool got_bios = false, got_sys = false;

    while (p + 4 <= end && !(got_bios && got_sys)) {
        const BYTE type = p[0];
        const BYTE len = p[1];
        if (len < 4 || p + len > end) break; // malformed / truncated -- stop rather than misread

        if (type == 0) {
            info.vendor  = SmbiosString(p, len, p[4]);
            info.version = SmbiosString(p, len, p[5]);
            if (len > 8) info.release_date = SmbiosString(p, len, p[8]);
            got_bios = true;
        } else if (type == 1) {
            info.sys_manufacturer = SmbiosString(p, len, p[4]);
            info.sys_product      = SmbiosString(p, len, p[5]);
            if (len > 7) info.sys_serial = SmbiosString(p, len, p[7]);
            if (len >= 0x18) {
                const BYTE* u = p + 8;
                char uuid_buf[40];
                std::snprintf(uuid_buf, sizeof(uuid_buf),
                    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6],
                    u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
                info.sys_uuid = QString::fromLatin1(uuid_buf);
            }
            got_sys = true;
        }

        // Skip the formatted section, then the trailing string table, which
        // is terminated by two consecutive NUL bytes.
        const BYTE* q = p + len;
        while (q + 1 < end && !(q[0] == 0 && q[1] == 0)) ++q;
        q += 2;
        p = q;
    }

    info.ok = got_bios;

    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
            0, KEY_READ, &key) == ERROR_SUCCESS) {
        DWORD val = 0, sz = sizeof(val), type = 0;
        if (RegQueryValueExW(key, L"UEFISecureBootEnabled", nullptr, &type,
                reinterpret_cast<BYTE*>(&val), &sz) == ERROR_SUCCESS && type == REG_DWORD) {
            info.secure_boot_known = true;
            info.secure_boot_enabled = (val != 0);
        }
        RegCloseKey(key);
    }
    return info;
}

// Background driver-signature scan touches page widgets via invokeMethod
// after possibly-slow WinVerifyTrust/catalog lookups per driver. Same
// use-after-free hazard as LAN Monitor's reverse-DNS scan (see
// main_window_lanmonitor.cpp) if the app quits mid-scan -- guarded the same
// way from the start here instead of repeating that bug.
std::atomic<bool> g_quitting{false};

} // namespace

QWidget* BuildKernelBiosPage(QWidget* parent) {
    (void)parent;
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(14);

    auto* title = new QLabel(QString::fromUtf8("Kernel / BIOS Scan"), page);
    title->setStyleSheet("color:#ECE4DA; font-size:28px; font-weight:700; background:transparent;");
    root->addWidget(title);
    auto* sub = new QLabel(QString::fromUtf8(
        "Loaded kernel drivers checked against Authenticode signatures (unsigned = possible "
        "rootkit/BYOVD), plus firmware identity read from SMBIOS and UEFI Secure Boot state. "
        "Firmware is read-only. For an UNSIGNED driver you can Block (disable its service) or "
        "Delete it (remove service + file) -- both need Administrator and ask for confirmation."), page);
    sub->setStyleSheet("color:#8B7355; font-size:9pt; background:transparent;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    // ── Firmware card ────────────────────────────────────────────────────
    auto* fw_card = new QFrame(page);
    fw_card->setStyleSheet(
        "QFrame { background:#1C1108; border:1px solid rgba(255,170,90,26); border-radius:10px; }");
    auto* fw_l = new QGridLayout(fw_card);
    fw_l->setContentsMargins(16, 14, 16, 14);
    fw_l->setHorizontalSpacing(24);
    fw_l->setVerticalSpacing(6);

    auto addField = [fw_l](int row, int col, const QString& label, const QString& value) {
        auto* l = new QLabel(label);
        l->setStyleSheet("color:#8B7355; font-size:8.5pt; background:transparent;");
        auto* v = new QLabel(value.isEmpty() ? QString("-") : value);
        v->setStyleSheet("color:#ECE4DA; font-size:9.5pt; font-weight:600; background:transparent;");
        v->setWordWrap(true);
        auto* box = new QVBoxLayout();
        box->setSpacing(1);
        box->addWidget(l);
        box->addWidget(v);
        fw_l->addLayout(box, row, col);
        return v;
    };

    const auto bios = ReadBiosInfo();
    addField(0, 0, QString::fromUtf8("BIOS Vendor"), bios.vendor);
    addField(0, 1, QString::fromUtf8("BIOS Version"), bios.version);
    addField(0, 2, QString::fromUtf8("BIOS Release Date"), bios.release_date);
    addField(1, 0, QString::fromUtf8("System Manufacturer"), bios.sys_manufacturer);
    addField(1, 1, QString::fromUtf8("System Product"), bios.sys_product);
    addField(1, 2, QString::fromUtf8("System Serial"), bios.sys_serial);
    addField(2, 0, QString::fromUtf8("System UUID"), bios.sys_uuid);

    const QString sb_text = !bios.secure_boot_known ? QString::fromUtf8("Unknown")
                           : bios.secure_boot_enabled ? QString::fromUtf8("Enabled")
                                                       : QString::fromUtf8("DISABLED");
    auto* sb_val = addField(2, 1, QString::fromUtf8("Secure Boot"), sb_text);
    sb_val->setStyleSheet(QString(
        "font-size:9.5pt; font-weight:700; background:transparent; color:%1;")
        .arg(!bios.secure_boot_known ? "#8B7355"
             : bios.secure_boot_enabled ? "#4ADE80" : "#FF3B50"));

    if (!bios.ok) {
        auto* warn = new QLabel(QString::fromUtf8(
            "Could not read SMBIOS firmware table on this machine."), fw_card);
        warn->setStyleSheet("color:#E6C24A; font-size:9pt; background:transparent;");
        fw_l->addWidget(warn, 3, 0, 1, 3);
    }
    root->addWidget(fw_card);

    // ── Driver scan controls ────────────────────────────────────────────
    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(12);
    auto* refresh_btn = new QPushButton(QString::fromUtf8("Rescan drivers"), page);
    refresh_btn->setCursor(Qt::PointingHandCursor);
    refresh_btn->setStyleSheet(
        "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #CC5500);"
        " border:none; border-radius:10px; color:#fff; font-size:10.5pt; font-weight:700; padding:10px 24px; }"
        "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9030,stop:1 #DD6600); }"
        "QPushButton:disabled { background:#33261A; color:#8B7355; }");
    ctl->addWidget(refresh_btn);

    auto* block_btn = new QPushButton(QString::fromUtf8("Block (disable)"), page);
    block_btn->setCursor(Qt::PointingHandCursor);
    block_btn->setEnabled(false);
    block_btn->setStyleSheet(
        "QPushButton { background:#3A2A12; border:1px solid #E6C24A; border-radius:10px;"
        " color:#E6C24A; font-size:10pt; font-weight:700; padding:10px 18px; }"
        "QPushButton:hover { background:#4A3616; }"
        "QPushButton:disabled { background:#241a10; color:#6B5A3C; border-color:#4A3A1C; }");
    ctl->addWidget(block_btn);

    auto* delete_btn = new QPushButton(QString::fromUtf8("Delete driver"), page);
    delete_btn->setCursor(Qt::PointingHandCursor);
    delete_btn->setEnabled(false);
    delete_btn->setStyleSheet(
        "QPushButton { background:#3A1414; border:1px solid #FF3B50; border-radius:10px;"
        " color:#FF6B7A; font-size:10pt; font-weight:700; padding:10px 18px; }"
        "QPushButton:hover { background:#4A1A1A; }"
        "QPushButton:disabled { background:#241010; color:#6B3C3C; border-color:#4A1C1C; }");
    ctl->addWidget(delete_btn);

    auto* status = new QLabel(QString::fromUtf8("Idle."), page);
    status->setStyleSheet("color:#C7B6A2; font-size:9.5pt; background:transparent;");
    ctl->addWidget(status, 1);
    root->addLayout(ctl);

    auto* table = new QTableWidget(0, 4, page);
    table->setHorizontalHeaderLabels({"Driver", "Path", "Base Address", "Signature"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);
    table->setStyleSheet(
        theme::TableQss());
    {
        auto* h = table->horizontalHeader();
        h->setStretchLastSection(true);
        h->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(1, QHeaderView::Stretch);
        h->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    }
    root->addWidget(table, 1);

    auto busy = std::make_shared<std::atomic<bool>>(false);

    QObject::connect(qApp, &QCoreApplication::aboutToQuit, page, [] { g_quitting.store(true); });

    auto refresh = [page, refresh_btn, status, table, busy] {
        if (busy->load()) return;
        busy->store(true);
        refresh_btn->setEnabled(false);
        table->setRowCount(0);
        status->setText(QString::fromUtf8("Enumerating drivers..."));
        std::thread([status, table, busy] {
            auto drivers = EnumerateDrivers();
            int done = 0;
            for (auto& d : drivers) {
                if (g_quitting.load()) { busy->store(false); return; }
                const std::wstring openable = ResolveOpenablePath(d.path.toStdWString());
                d.is_signed = avpe::IsAuthenticodeSigned(NarrowUtf8(openable));
                if (d.is_signed) {
                    d.note = "Signed";
                    d.risk = 0;
                } else if (!CanOpenForRead(openable)) {
                    // Could not open the file to verify -- NOT proof it's unsigned.
                    // A path this tool failed to resolve, or a genuinely locked
                    // file, lands here. Neutral label + medium risk so a readable-
                    // but-unresolved legit driver isn't mislabeled a rootkit, and
                    // (being <70) Block/Delete stay disabled for it.
                    d.note = "Unverified -- could not open file to check signature";
                    d.risk = 40;
                } else {
                    // File opened fine, yet neither an embedded nor catalog
                    // signature validated -- this is the real BYOVD/rootkit signal.
                    d.note = "UNSIGNED -- possible rootkit / BYOVD";
                    d.risk = 90;
                }
                ++done;
                if (done % 20 == 0 && !g_quitting.load()) {
                    const int n = done, total = static_cast<int>(drivers.size());
                    QMetaObject::invokeMethod(status, [status, n, total] {
                        status->setText(QString::fromUtf8("Checking signatures... %1/%2").arg(n).arg(total));
                    }, Qt::QueuedConnection);
                }
            }
            if (g_quitting.load()) { busy->store(false); return; }

            int flagged = 0, unverified = 0;
            for (const auto& d : drivers) {
                if (d.risk >= 70) ++flagged;
                else if (d.risk >= 40) ++unverified;
            }
            const int total = static_cast<int>(drivers.size());
            QMetaObject::invokeMethod(table, [table, drivers] {
                for (const auto& d : drivers) {
                    const int row = table->rowCount();
                    table->insertRow(row);
                    auto* name_item = new QTableWidgetItem(d.name);
                    name_item->setData(Qt::UserRole, d.risk); // used to gate Block/Delete
                    table->setItem(row, 0, name_item);
                    table->setItem(row, 1, new QTableWidgetItem(d.path));
                    table->setItem(row, 2, new QTableWidgetItem(d.base_addr));
                    auto* note = new QTableWidgetItem(d.note);
                    note->setForeground(RiskColor(d.risk));
                    table->setItem(row, 3, note);
                }
            }, Qt::QueuedConnection);
            QMetaObject::invokeMethod(status, [status, total, flagged, unverified] {
                status->setText(QString::fromUtf8(
                    "%1 drivers  -  %2 unsigned (flagged)  -  %3 unverified (could not open)")
                    .arg(total).arg(flagged).arg(unverified));
            }, Qt::QueuedConnection);
            busy->store(false);
        }).detach();
    };

    QObject::connect(refresh_btn, &QPushButton::clicked, page, refresh);

    // ── Block: disable the driver's kernel service (no load at next boot) ──
    QObject::connect(block_btn, &QPushButton::clicked, page, [page, table, status] {
        const int row = table->currentRow();
        if (row < 0 || !table->item(row, 0)) return;
        const QString name = table->item(row, 0)->text();
        const QString path = table->item(row, 1) ? table->item(row, 1)->text() : QString();
        const QString svc  = ServiceNameFromDriver(name);

        const auto ret = QMessageBox::warning(page,
            QString::fromUtf8("Block kernel driver"),
            QString::fromUtf8(
                "Disable the kernel service \"%1\"?\n\nDriver file: %2\n\n"
                "This sets its start type to DISABLED so it will NOT load on next boot. "
                "The instance already in memory keeps running until you reboot.\n\n"
                "WARNING: disabling a legitimate driver can break hardware, networking, "
                "or prevent Windows from booting. Only proceed if you are sure it is "
                "malicious. Requires running TeoAV as Administrator.")
                .arg(svc, path.isEmpty() ? name : path),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
        if (ret != QMessageBox::Yes) return;

        RunSc({"stop", svc}); // best-effort; boot/loaded drivers often refuse to stop
        const auto cfg = RunSc({"config", svc, "start=", "disabled"});

        if (cfg.code == 0) {
            status->setText(QString::fromUtf8("Blocked \"%1\" (disabled at boot). Reboot to fully unload.").arg(svc));
            QMessageBox::information(page, QString::fromUtf8("Blocked"),
                QString::fromUtf8("Service \"%1\" set to DISABLED. It will not load after reboot.").arg(svc));
        } else if (ScLooksLikeAccessDenied(cfg)) {
            QMessageBox::critical(page, QString::fromUtf8("Access denied"),
                QString::fromUtf8("Blocking a kernel service needs Administrator rights.\n"
                                  "Close TeoAV and relaunch it as Administrator, then try again."));
        } else {
            QMessageBox::warning(page, QString::fromUtf8("Could not block"),
                QString::fromUtf8("sc config failed for \"%1\":\n\n%2").arg(svc, cfg.output));
        }
    });

    // ── Delete: remove the service registration + attempt to delete the .sys ──
    QObject::connect(delete_btn, &QPushButton::clicked, page, [page, table, status] {
        const int row = table->currentRow();
        if (row < 0 || !table->item(row, 0)) return;
        const QString name = table->item(row, 0)->text();
        const QString path = table->item(row, 1) ? table->item(row, 1)->text() : QString();
        const QString svc  = ServiceNameFromDriver(name);

        const auto ret = QMessageBox::warning(page,
            QString::fromUtf8("Delete kernel driver"),
            QString::fromUtf8(
                "Permanently remove the kernel service \"%1\" and try to delete its file?\n\n"
                "Driver file: %2\n\n"
                "This runs `sc delete %1` (removes the service registration) and then attempts "
                "to delete the .sys file. A driver that is currently loaded cannot have its file "
                "deleted until you reboot -- the service removal still takes effect.\n\n"
                "WARNING: this is irreversible. Deleting a legitimate driver can break the system. "
                "Only proceed if you are sure it is malicious. Requires Administrator.")
                .arg(svc, path.isEmpty() ? name : path),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
        if (ret != QMessageBox::Yes) return;

        RunSc({"stop", svc}); // best-effort
        const auto del = RunSc({"delete", svc});

        if (del.code != 0 && ScLooksLikeAccessDenied(del)) {
            QMessageBox::critical(page, QString::fromUtf8("Access denied"),
                QString::fromUtf8("Deleting a kernel service needs Administrator rights.\n"
                                  "Close TeoAV and relaunch it as Administrator, then try again."));
            return;
        }

        // Attempt to delete the file too (usually fails while the driver is
        // still resident -- reported honestly rather than pretended).
        bool file_deleted = false;
        QString file_err;
        if (!path.isEmpty()) {
            const std::wstring wpath = ResolveOpenablePath(path.toStdWString());
            if (DeleteFileW(wpath.c_str())) {
                file_deleted = true;
            } else {
                const DWORD e = GetLastError();
                file_err = (e == ERROR_SHARING_VIOLATION || e == ERROR_ACCESS_DENIED)
                    ? QString::fromUtf8("file is locked (driver still loaded) -- delete completes after reboot")
                    : QString::fromUtf8("DeleteFile error %1").arg(e);
            }
        }

        const bool svc_ok = (del.code == 0);
        QString msg = svc_ok
            ? QString::fromUtf8("Service \"%1\" deleted.").arg(svc)
            : QString::fromUtf8("sc delete \"%1\" returned:\n%2\n").arg(svc, del.output);
        msg += file_deleted ? QString::fromUtf8("\nDriver file deleted.")
                            : QString::fromUtf8("\nDriver file NOT deleted: %1").arg(
                                  file_err.isEmpty() ? QString::fromUtf8("no path") : file_err);
        QMessageBox::information(page, QString::fromUtf8("Delete driver"), msg);
        status->setText(svc_ok ? QString::fromUtf8("Deleted service \"%1\". Rescan to refresh.").arg(svc)
                               : QString::fromUtf8("Delete of \"%1\" incomplete -- see dialog.").arg(svc));
    });

    auto* sync = new QTimer(page);
    sync->setInterval(300);
    QObject::connect(sync, &QTimer::timeout, refresh_btn,
                     [refresh_btn, block_btn, delete_btn, table, busy] {
        const bool idle = !busy->load();
        refresh_btn->setEnabled(idle);
        // Block/Delete only for a selected UNSIGNED (flagged, risk>=70) driver,
        // so a stray click can't touch a legitimate signed one.
        bool flagged = false;
        if (idle) {
            const int row = table->currentRow();
            if (row >= 0 && table->item(row, 0))
                flagged = table->item(row, 0)->data(Qt::UserRole).toInt() >= 70;
        }
        block_btn->setEnabled(flagged);
        delete_btn->setEnabled(flagged);
    });
    sync->start();
    refresh(); // initial population

    return page;
}

} // namespace avdashboard
