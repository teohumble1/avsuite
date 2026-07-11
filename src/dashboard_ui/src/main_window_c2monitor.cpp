// main_window_c2monitor.cpp — C2 Monitor: live external TCP connections +
// on-demand VirusTotal IP reputation lookup + real firewall block.
//
// Previously this page populated its table with 13 hardcoded fake "C2
// connections" (fake malware domains, fake CRITICAL/Active status) shown
// unconditionally on every launch -- actively misleading for a security
// product. Replaced with real data: GetExtendedTcpTable (same API Firewall
// Pro already uses) filtered to established, non-private remote addresses.
// Reputation is left "Not checked" until the user explicitly requests a
// real VirusTotal lookup (reuses MainWindow::LookupVtIoc, already built for
// the OSINT Hub page) -- no fabricated threat verdicts.

#include "main_window.hpp"
#include "theme.hpp"
#include "av_quit_guard.hpp"

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QHeaderView>
#include <QTimer>
#include <QDateTime>
#include <QColor>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QMenu>
#include <QAction>
#include <QProcess>
#include <QMetaObject>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <map>
#include <set>
#include <thread>
#include <vector>

namespace avdashboard {

namespace {

struct C2Connection {
    QString timestamp;
    QString process;
    QString ip;
    QString port;
    QString protocol;
    QString reputation; // "Not checked" until a real VT lookup is run
    QString status;     // "Active" or "Blocked"
};

std::map<DWORD, QString> PidNames() {
    std::map<DWORD, QString> m;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return m;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do { m[pe.th32ProcessID] = QString::fromWCharArray(pe.szExeFile); }
        while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return m;
}

QString IpStr(DWORD addr) {
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return QString::fromLatin1(buf);
}

bool IsPrivate(DWORD addrNet) {
    const DWORD a = ntohl(addrNet);
    const BYTE b1 = (a >> 24) & 0xFF, b2 = (a >> 16) & 0xFF;
    if (b1 == 10) return true;
    if (b1 == 192 && b2 == 168) return true;
    if (b1 == 172 && b2 >= 16 && b2 <= 31) return true;
    if (b1 == 127) return true;
    if (a == 0) return true;
    return false;
}

// Only established connections to a non-private remote address -- a
// "C2 monitor" caring about listening sockets or LAN traffic isn't useful;
// Firewall Pro's page already covers the general connection list.
std::vector<C2Connection> ExternalConnections() {
    std::vector<C2Connection> out;
    const auto names = PidNames();
    const QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");

    DWORD size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        return out;
    std::vector<BYTE> buf(size);
    auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    if (GetExtendedTcpTable(t, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return out;

    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& r = t->table[i];
        if (r.dwState != MIB_TCP_STATE_ESTAB) continue;
        if (IsPrivate(r.dwRemoteAddr)) continue;

        C2Connection c;
        c.timestamp = ts;
        auto it = names.find(r.dwOwningPid);
        c.process = it != names.end() ? it->second : QString("pid %1").arg(r.dwOwningPid);
        c.ip = IpStr(r.dwRemoteAddr);
        c.port = QString::number(ntohs(static_cast<u_short>(r.dwRemotePort)));
        c.protocol = "TCP";
        c.reputation = "Not checked";
        c.status = "Active";
        out.push_back(std::move(c));
    }
    return out;
}

QString RuleName(const QString& ip) { return QString("AvSuite C2 block %1").arg(ip); }

std::set<QString> QueryBlockedIps() {
    std::set<QString> out;
    QProcess p;
    p.start("netsh", {"advfirewall", "firewall", "show", "rule", "name=all"});
    if (!p.waitForFinished(5000)) { p.kill(); return out; }
    const QString text = QString::fromLocal8Bit(p.readAllStandardOutput());
    const QString marker = "AvSuite C2 block ";
    int pos = 0;
    while ((pos = text.indexOf(marker, pos)) != -1) {
        const int start = pos + marker.size();
        int end = start;
        while (end < text.size() && !text[end].isSpace()) ++end;
        out.insert(text.mid(start, end - start));
        pos = end;
    }
    return out;
}

bool BlockIp(const QString& ip) {
    QProcess p;
    p.start("netsh", {"advfirewall", "firewall", "add", "rule",
                       QString("name=%1").arg(RuleName(ip)), "dir=out", "action=block",
                       QString("remoteip=%1").arg(ip)});
    if (!p.waitForFinished(5000)) { p.kill(); return false; }
    return p.exitCode() == 0;
}

} // namespace

QWidget* BuildC2MonitorPage(QWidget* parent) {
    auto* win = qobject_cast<MainWindow*>(parent);
    auto* page = new QWidget(parent);
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto* header = new QFrame;
    header->setStyleSheet("background-color:#1C1108; border-bottom:1px solid #333;");
    header->setMaximumHeight(50);
    auto* h_layout = new QHBoxLayout(header);
    h_layout->setContentsMargins(16, 8, 16, 8);

    auto* title = new QLabel("C2 Monitor");
    title->setStyleSheet("color:#FF5A6A; font-weight:bold; font-size:14px;");
    h_layout->addWidget(title);

    auto* subtitle = new QLabel("Live outbound connections to non-private IPs. Reputation is checked on demand (right-click), never assumed.");
    subtitle->setStyleSheet("color:#8B7355; font-size:9pt;");
    h_layout->addWidget(subtitle);

    auto* export_btn = new QPushButton("Export");
    export_btn->setMaximumWidth(100);
    export_btn->setStyleSheet(
        "QPushButton { background:#33261A; color:#FFF; border:1px solid #4ADE80; "
        "border-radius:4px; padding:6px 12px; }"
        "QPushButton:hover { background:#4ADE80; }");

    auto* clear_btn = new QPushButton("Clear");
    clear_btn->setMaximumWidth(100);
    clear_btn->setStyleSheet(
        "QPushButton { background:#333; color:#FFF; border:1px solid #555; "
        "border-radius:4px; padding:6px 12px; }"
        "QPushButton:hover { background:#444; }");
    h_layout->addStretch();
    h_layout->addWidget(export_btn);
    h_layout->addWidget(clear_btn);

    layout->addWidget(header);

    auto* table = new QTableWidget;
    table->setColumnCount(7);
    table->setHorizontalHeaderLabels(QStringList()
        << "Timestamp" << "Process" << "Remote IP" << "Port"
        << "Protocol" << "Reputation" << "Status");

    table->horizontalHeader()->setStyleSheet(
        "QHeaderView::section { background:#222; color:#FFF; padding:6px; "
        "border-right:1px solid #333; font-weight:bold; }");
    table->setStyleSheet(
        theme::TableQss());
    table->setAlternatingRowColors(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setStretchLastSection(true);
    table->setColumnWidth(0, 90);
    table->setColumnWidth(1, 180);
    table->setColumnWidth(2, 140);
    table->setColumnWidth(3, 70);
    table->setColumnWidth(4, 70);

    layout->addWidget(table);

    if (win) ArmQuitGuard(page);

    // Context menu: real actions only -- no more "Scanning..."/"Fetching..."
    // dialogs that claimed to do work they never did.
    table->setContextMenuPolicy(Qt::CustomContextMenu);
    QObject::connect(table, &QTableWidget::customContextMenuRequested, page, [table, win, page](const QPoint& pos) {
        int row = table->rowAt(pos.y());
        if (row < 0) return;
        const QString ip = table->item(row, 2)->text();

        QMenu menu;
        menu.setStyleSheet(
            "QMenu { background:#1C1108; color:#FFF; border:1px solid #444; }"
            "QMenu::item:selected { background:#FF5A6A; color:#000; }");

        const QString process = table->item(row, 1)->text();
        auto* hunt_action = menu.addAction("Ask AI about this connection");
        QObject::connect(hunt_action, &QAction::triggered, page, [win, process, ip]() {
            if (win) {
                win->OpenAiWithPrompt(QString(
                    "Process \"%1\" has an active outbound connection to %2. "
                    "Should I be concerned? What should I check next (parent process, "
                    "loaded modules, whether this IP/process is expected)?")
                    .arg(process, ip));
            }
        });

        auto* osint_action = menu.addAction("Check reputation (VirusTotal)");
        QObject::connect(osint_action, &QAction::triggered, page, [win, table, row, ip, page]() {
            if (!win) return;
            table->item(row, 5)->setText("Checking...");
            std::thread([win, table, row, ip, page]() {
                const QString result = win->LookupVtIoc("ip", ip);
                if (AppQuitting().load()) return;
                QMetaObject::invokeMethod(page, [table, row, result]() {
                    if (row >= table->rowCount()) return; // table may have been cleared/refreshed since
                    auto* item = table->item(row, 5);
                    if (!item) return;
                    item->setText(result.left(40));
                    if (result.contains("malicious", Qt::CaseInsensitive) ||
                        result.contains("Malicious", Qt::CaseInsensitive)) {
                        item->setForeground(QColor(255, 107, 107));
                    } else {
                        item->setForeground(QColor(74, 222, 128));
                    }
                }, Qt::QueuedConnection);
            }).detach();
        });

        menu.addSeparator();
        auto* block_action = menu.addAction("Block IP (Windows Firewall)");
        QObject::connect(block_action, &QAction::triggered, page, [ip, table, row]() {
            if (BlockIp(ip)) {
                table->item(row, 6)->setText("Blocked");
                table->item(row, 6)->setForeground(QColor(74, 222, 128));
            } else {
                QMessageBox::warning(table, "Block IP",
                    "Could not add the firewall rule. Try running as Administrator.");
            }
        });

        auto* dismiss_action = menu.addAction("Dismiss row");
        QObject::connect(dismiss_action, &QAction::triggered, page, [table, row]() {
            table->removeRow(row);
        });

        menu.exec(table->mapToGlobal(pos));
    });

    auto blocked_ips = std::make_shared<std::set<QString>>();

    auto refresh = [table, blocked_ips]() {
        *blocked_ips = QueryBlockedIps();
        table->setRowCount(0);
        for (const auto& c : ExternalConnections()) {
            const int row = table->rowCount();
            table->insertRow(row);

            const bool is_blocked = blocked_ips->count(c.ip) > 0;

            auto set = [table, row](int col, const QString& text, QColor color) {
                auto* item = new QTableWidgetItem(text);
                item->setForeground(color);
                table->setItem(row, col, item);
            };
            set(0, c.timestamp, QColor(180, 180, 180));
            set(1, c.process, QColor(200, 200, 200));
            set(2, c.ip, QColor(160, 160, 160));
            set(3, c.port, QColor(140, 140, 140));
            set(4, c.protocol, QColor(140, 140, 140));
            set(5, c.reputation, QColor(140, 140, 140));
            set(6, is_blocked ? "Blocked" : c.status,
                is_blocked ? QColor(74, 222, 128) : QColor(255, 200, 87));
        }
    };

    refresh();
    auto* timer = new QTimer(page);
    timer->setInterval(5000);
    QObject::connect(timer, &QTimer::timeout, page, refresh);
    timer->start();

    QObject::connect(export_btn, &QPushButton::clicked, page, [table]() {
        if (table->rowCount() == 0) {
            QMessageBox::warning(table, "Export", "No connections to export.");
            return;
        }
        QString filename = QFileDialog::getSaveFileName(
            table, "Export C2 Monitor", "", "CSV Files (*.csv);;Text Files (*.txt)");
        if (filename.isEmpty()) return;

        QFile file(filename);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::critical(table, "Export", "Cannot open file for writing.");
            return;
        }
        QTextStream out(&file);
        QStringList header;
        for (int col = 0; col < table->columnCount(); ++col) header << table->horizontalHeaderItem(col)->text();
        out << header.join(",") << "\n";
        for (int row = 0; row < table->rowCount(); ++row) {
            QStringList row_data;
            for (int col = 0; col < table->columnCount(); ++col) {
                QString cell_text = table->item(row, col)->text();
                if (cell_text.contains(",") || cell_text.contains("\"")) {
                    cell_text = "\"" + cell_text.replace("\"", "\"\"") + "\"";
                }
                row_data << cell_text;
            }
            out << row_data.join(",") << "\n";
        }
        file.close();
        QMessageBox::information(table, "Export",
            QString("Exported %1 connections to:\n%2").arg(table->rowCount()).arg(filename));
    });

    QObject::connect(clear_btn, &QPushButton::clicked, page, [table]() { table->setRowCount(0); });

    return page;
}

} // namespace avdashboard
