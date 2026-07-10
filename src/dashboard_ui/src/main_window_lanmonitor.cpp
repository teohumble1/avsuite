// main_window_lanmonitor.cpp — LAN device monitor.
//
// Enumerates devices on the local network (ARP cache) and flags anomalies that
// often accompany compromised / botnet-infected devices or MITM on the LAN:
//   * Duplicate MAC across several IPs  -> possible ARP spoofing / MITM
//   * Gateway IP bound to an unexpected MAC (checked as duplicate-of-many)
// Shows IP, MAC, resolved hostname, vendor (OUI), and notes. Reverse DNS runs
// on a background thread so the UI never blocks. ASCII labels (MSVC no /utf-8).

#include "main_window.hpp"
#include "theme.hpp"
#include "hunt_toolbar.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QCoreApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace avdashboard {
namespace {

struct LanDevice {
    QString ip;
    QString mac;
    QString host;
    QString vendor;
    QString note;
    int     risk = 0;
};

QString MacString(const BYTE* addr, DWORD len) {
    QString s;
    for (DWORD i = 0; i < len; ++i) {
        if (i) s += ':';
        s += QString("%1").arg(addr[i], 2, 16, QLatin1Char('0')).toUpper();
    }
    return s;
}

// Tiny OUI → vendor hint table (first 3 MAC bytes). Best-effort only.
QString VendorFromMac(const QString& mac) {
    static const std::map<QString, QString> oui = {
        {"00:50:56", "VMware"}, {"00:0C:29", "VMware"}, {"00:1C:14", "VMware"},
        {"08:00:27", "VirtualBox"}, {"52:54:00", "QEMU/KVM"},
        {"00:15:5D", "Hyper-V"}, {"DC:A6:32", "Raspberry Pi"}, {"B8:27:EB", "Raspberry Pi"},
        {"00:1A:11", "Google"}, {"3C:5A:B4", "Google"}, {"F4:F5:D8", "Google"},
        {"00:17:88", "Philips Hue"}, {"AC:DE:48", "Apple"}, {"F0:18:98", "Apple"},
    };
    const QString prefix = mac.left(8);
    auto it = oui.find(prefix);
    return it != oui.end() ? it->second : QString("Unknown");
}

std::vector<LanDevice> EnumerateArp() {
    std::vector<LanDevice> out;
    ULONG size = 0;
    if (GetIpNetTable(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER) return out;
    std::vector<BYTE> buf(size);
    auto* table = reinterpret_cast<MIB_IPNETTABLE*>(buf.data());
    if (GetIpNetTable(table, &size, FALSE) != NO_ERROR) return out;

    // Count MAC occurrences to spot duplicates (ARP spoofing signal).
    std::map<QString, int> macCount;
    struct Row { QString ip, mac; DWORD type; };
    std::vector<Row> rows;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& e = table->table[i];
        if (e.dwPhysAddrLen == 0) continue;                 // incomplete
        if (e.Type == MIB_IPNET_TYPE_INVALID) continue;
        char ipbuf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &e.dwAddr, ipbuf, sizeof(ipbuf));
        const QString ip = QString::fromLatin1(ipbuf);
        if (ip.startsWith("224.") || ip.endsWith(".255") || ip == "255.255.255.255") continue; // multicast/bcast
        const QString mac = MacString(e.bPhysAddr, e.dwPhysAddrLen);
        if (mac == "FF:FF:FF:FF:FF:FF" || mac.startsWith("01:00:5E")) continue;
        macCount[mac]++;
        rows.push_back({ ip, mac, static_cast<DWORD>(e.Type) });
    }
    for (const auto& r : rows) {
        LanDevice d;
        d.ip = r.ip;
        d.mac = r.mac;
        d.vendor = VendorFromMac(r.mac);
        if (macCount[r.mac] >= 3) {           // one MAC answering for many IPs
            d.note = "Duplicate MAC on multiple IPs - possible ARP spoofing / MITM";
            d.risk = 85;
        } else if (r.type == MIB_IPNET_TYPE_STATIC) {
            d.note = "Static ARP entry";
            d.risk = 10;
        } else {
            d.note = "OK";
            d.risk = 0;
        }
        out.push_back(std::move(d));
    }
    return out;
}

QString ReverseDns(const QString& ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.toLatin1().constData(), &sa.sin_addr) != 1) return {};
    char host[NI_MAXHOST] = {};
    if (getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa),
                    host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
        return QString::fromLatin1(host);
    }
    return {};
}

QColor RiskColor(int r) {
    if (r >= 70) return QColor(0xFF, 0x3B, 0x50);
    if (r >= 10) return QColor(0xE6, 0xC2, 0x4A);
    return QColor(0x4A, 0xDE, 0x80);
}

// The refresh scan runs on a detached background thread (reverse DNS is
// serial + blocking and can take many seconds across a whole LAN), then
// touches the page's widgets via QMetaObject::invokeMethod. If the app is
// closed mid-scan, those widgets are destroyed before the thread finishes,
// and invokeMethod(table, ...) dereferences freed memory -> crash. Once this
// flag flips, the thread skips every widget touch instead.
std::atomic<bool> g_quitting{false};

} // namespace

QWidget* BuildLanMonitorPage(QWidget* parent) {
    (void)parent;
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(12);

    auto* refresh_btn = new QPushButton(QString::fromUtf8("Refresh devices"), page);
    refresh_btn->setObjectName("PrimaryBtn");
    refresh_btn->setCursor(Qt::PointingHandCursor);
    root->addWidget(theme::BuildPageHeader(
        "LAN Device Monitor",
        "Inventories devices on your local network (ARP) and flags anomalies linked to "
        "compromised/botnet devices or MITM: duplicate MAC across IPs (ARP spoofing), etc.",
        refresh_btn));

    auto* status = new QLabel(QString::fromUtf8("Idle."), page);
    status->setStyleSheet(QString("color:%1; font-size:%2px; background:transparent;")
                              .arg(theme::Muted).arg(theme::FontBody));
    // Row for status + the shared Clean/Export buttons (inserted at index 1/2 below).
    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(theme::Space3);
    ctl->addWidget(status, 1);
    root->addLayout(ctl);

    auto* table = new QTableWidget(0, 5, page);
    table->setHorizontalHeaderLabels({"IP", "MAC", "Hostname", "Vendor", "Note"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setStyleSheet(theme::TableQss());
    {
        auto* h = table->horizontalHeader();
        h->setStretchLastSection(true);
        h->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(2, QHeaderView::Stretch);
        h->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    }
    root->addWidget(table, 1);

    auto busy = std::make_shared<std::atomic<bool>>(false);

    QObject::connect(qApp, &QCoreApplication::aboutToQuit, page, [] { g_quitting.store(true); });

    auto refresh = [page, refresh_btn, status, table, busy] {
        if (busy->load()) return;
        busy->store(true);
        refresh_btn->setEnabled(false);
        table->setRowCount(0);
        status->setText(QString::fromUtf8("Scanning ARP table..."));
        std::thread([status, table, busy] {
            auto devices = EnumerateArp();
            // Resolve hostnames (bounded) on this background thread. Bail out
            // early if the app is quitting instead of grinding through the
            // rest of a possibly-long serial DNS lookup list.
            for (auto& d : devices) {
                if (g_quitting.load()) { busy->store(false); return; }
                d.host = ReverseDns(d.ip);
            }
            if (g_quitting.load()) { busy->store(false); return; }
            int flagged = 0;
            for (const auto& d : devices) if (d.risk >= 70) ++flagged;
            const int total = static_cast<int>(devices.size());
            QMetaObject::invokeMethod(table, [table, devices] {
                for (const auto& d : devices) {
                    const int row = table->rowCount();
                    table->insertRow(row);
                    QString bg; if (d.risk >= 90) bg = "#3A1F1F"; else if (d.risk >= 70) bg = "#3A2F1F"; else if (d.risk >= 50) bg = "#2F3A1F"; else bg = "#1F2F1F";
                    auto* ip = new QTableWidgetItem(d.ip); ip->setBackground(QColor(bg)); table->setItem(row, 0, ip);
                    auto* mac = new QTableWidgetItem(d.mac); mac->setBackground(QColor(bg)); table->setItem(row, 1, mac);
                    auto* host = new QTableWidgetItem(d.host.isEmpty() ? QString("-") : d.host); host->setBackground(QColor(bg)); table->setItem(row, 2, host);
                    auto* vendor = new QTableWidgetItem(d.vendor); vendor->setBackground(QColor(bg)); table->setItem(row, 3, vendor);
                    auto* note = new QTableWidgetItem(d.note); note->setForeground(RiskColor(d.risk)); note->setBackground(QColor(bg)); table->setItem(row, 4, note);
                }
            }, Qt::QueuedConnection);
            QMetaObject::invokeMethod(status, [status, total, flagged] {
                status->setText(QString::fromUtf8("Found %1 devices, %2 flagged.").arg(total).arg(flagged));
            }, Qt::QueuedConnection);
            busy->store(false);
        }).detach();
    };

    QObject::connect(refresh_btn, &QPushButton::clicked, page, refresh);

    // Clean + Export (shared helper): Refresh | Clean | Export | status.
    auto* clean_btn  = MakeCleanButton(page, table, status);
    auto* export_btn = MakeExportButton(page, table,
                                        QString::fromUtf8("lan_devices.csv"), status);
    ctl->insertWidget(1, clean_btn);
    ctl->insertWidget(2, export_btn);

    // Keep the buttons in sync with the worker.
    auto* sync = new QTimer(page);
    sync->setInterval(300);
    QObject::connect(sync, &QTimer::timeout, refresh_btn,
                     [refresh_btn, clean_btn, export_btn, table, busy] {
        const bool b = busy->load();
        const bool has_rows = table->rowCount() > 0;
        refresh_btn->setEnabled(!b);
        clean_btn->setEnabled(!b && has_rows);
        export_btn->setEnabled(!b && has_rows);
    });
    sync->start();
    refresh(); // initial population

    return page;
}

} // namespace avdashboard
