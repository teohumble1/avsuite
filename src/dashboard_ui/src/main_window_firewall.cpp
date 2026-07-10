// main_window_firewall.cpp — Firewall Pro: live per-process connection monitor + block.
//
// Lists active TCP connections with the owning process (GetExtendedTcpTable),
// flags external/listening sockets, and can block a remote IP by adding an
// outbound Windows Firewall rule (netsh advfirewall — needs admin). ASCII labels.

#include "main_window.hpp"
#include "theme.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace avdashboard {
namespace {

struct Conn {
    QString proc;
    DWORD   pid = 0;
    QString local;
    QString remote;
    QString remoteIp;
    QString state;
    QString note;
    int     risk = 0;
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

const char* StateName(DWORD s) {
    switch (s) {
        case MIB_TCP_STATE_CLOSED:      return "CLOSED";
        case MIB_TCP_STATE_LISTEN:      return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:    return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:    return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:       return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:   return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:   return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:     return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:    return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB:  return "DELETE_TCB";
        default:                        return "?";
    }
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

std::vector<Conn> Connections() {
    std::vector<Conn> out;
    const auto names = PidNames();
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
        Conn c;
        c.pid = r.dwOwningPid;
        auto it = names.find(c.pid);
        c.proc = it != names.end() ? it->second : QString("pid %1").arg(c.pid);
        c.local  = IpStr(r.dwLocalAddr) + ":" + QString::number(ntohs(static_cast<u_short>(r.dwLocalPort)));
        c.state  = QString::fromLatin1(StateName(r.dwState));
        if (r.dwState == MIB_TCP_STATE_LISTEN) {
            c.remote = "*";
            c.note = "Listening";
            c.risk = 5;
        } else {
            c.remoteIp = IpStr(r.dwRemoteAddr);
            c.remote = c.remoteIp + ":" + QString::number(ntohs(static_cast<u_short>(r.dwRemotePort)));
            if (!IsPrivate(r.dwRemoteAddr)) {
                c.note = "External connection";
                c.risk = 20;
            } else {
                c.note = "Local/LAN";
                c.risk = 0;
            }
        }
        out.push_back(std::move(c));
    }
    return out;
}

QColor RiskColor(int r) {
    if (r >= 60) return QColor(0xFF, 0x3B, 0x50);
    if (r >= 20) return QColor(0xFF, 0x7A, 0x00);
    return QColor(0x9A, 0x8A, 0x76);
}

// AvSuite's own outbound-block rules are always named "AvSuite block <ip>",
// so the currently-blocked set can be read straight back out of Windows
// Firewall instead of tracked separately -- stays correct even if the app
// was restarted since the rule was added, or the user removed it by hand.
QString RuleName(const QString& ip) { return QString("AvSuite block %1").arg(ip); }

std::set<QString> QueryBlockedIps() {
    std::set<QString> out;
    QProcess p;
    p.start("netsh", {"advfirewall", "firewall", "show", "rule", "name=all"});
    if (!p.waitForFinished(5000)) { p.kill(); return out; }
    const QString text = QString::fromLocal8Bit(p.readAllStandardOutput());
    static const QRegularExpression re(R"(Rule Name:\s*AvSuite block (\S+))");
    auto it = re.globalMatch(text);
    while (it.hasNext()) out.insert(it.next().captured(1));
    return out;
}

} // namespace

QWidget* BuildFirewallPage(QWidget* parent) {
    (void)parent;
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(12);

    auto* title = new QLabel(QString::fromUtf8("Firewall Pro"), page);
    title->setStyleSheet("color:#ECE4DA; font-size:16pt; font-weight:700; background:transparent;");
    root->addWidget(title);
    auto* sub = new QLabel(QString::fromUtf8(
        "Live per-process network connections, auto-refreshed. Select a row to block its "
        "remote IP in real time (adds an outbound Windows Firewall rule; run as "
        "Administrator to apply) -- blocked rows are marked in red, and can be unblocked "
        "instantly from either the table or the Blocked IPs list below."), page);
    sub->setStyleSheet("color:#8B7355; font-size:9pt; background:transparent;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(12);
    auto* refresh_btn = new QPushButton(QString::fromUtf8("Refresh"), page);
    auto* block_btn = new QPushButton(QString::fromUtf8("Block remote IP"), page);
    for (auto* b : { refresh_btn, block_btn }) {
        b->setCursor(Qt::PointingHandCursor);
        b->setStyleSheet(
            "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #CC5500);"
            " border:none; border-radius:10px; color:#fff; font-size:10.5pt; font-weight:700; padding:9px 22px; }"
            "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9030,stop:1 #DD6600); }");
    }
    auto* unblock_btn = new QPushButton(QString::fromUtf8("Unblock remote IP"), page);
    unblock_btn->setCursor(Qt::PointingHandCursor);
    unblock_btn->setStyleSheet(
        "QPushButton { background:#1C1108; border:1px solid #4ADE80; border-radius:10px;"
        "              color:#4ADE80; font-size:10.5pt; font-weight:700; padding:9px 22px; }"
        "QPushButton:hover { background:#4ADE8030; }");
    ctl->addWidget(refresh_btn);
    ctl->addWidget(block_btn);
    ctl->addWidget(unblock_btn);
    auto* status = new QLabel(page);
    status->setStyleSheet("color:#C7B6A2; font-size:9.5pt; background:transparent;");
    ctl->addWidget(status, 1);
    root->addLayout(ctl);

    auto* table = new QTableWidget(0, 6, page);
    table->setHorizontalHeaderLabels({"Process", "PID", "Local", "Remote", "State", "Status"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);
    table->setStyleSheet(
        theme::TableQss());
    {
        auto* h = table->horizontalHeader();
        h->setStretchLastSection(true);
        h->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(3, QHeaderView::Stretch);
        h->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    }
    root->addWidget(table, 2);

    auto* blocked_lbl = new QLabel(QString::fromUtf8("Blocked IPs (AvSuite rules)"), page);
    blocked_lbl->setStyleSheet("color:#8B7355; font-size:9pt; font-weight:700; background:transparent;");
    root->addWidget(blocked_lbl);

    auto* blocked_table = new QTableWidget(0, 2, page);
    blocked_table->setHorizontalHeaderLabels({"Blocked remote IP", ""});
    blocked_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    blocked_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    blocked_table->verticalHeader()->setVisible(false);
    blocked_table->setShowGrid(false);
    blocked_table->setAlternatingRowColors(true);
    blocked_table->setStyleSheet(
        theme::TableQss());
    blocked_table->horizontalHeader()->setStretchLastSection(false);
    blocked_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    blocked_table->setColumnWidth(1, 100);
    blocked_table->setMaximumHeight(150);
    root->addWidget(blocked_table, 1);

    auto unblockIp = [page](const QString& ip) {
        const QStringList args{ "advfirewall", "firewall", "delete", "rule",
            QString("name=%1").arg(RuleName(ip)) };
        const int rc = QProcess::execute("netsh", args);
        if (rc != 0) {
            QMessageBox::warning(page, QString::fromUtf8("Could not unblock"),
                QString::fromUtf8("netsh failed (rc=%1). Run TeoAvSuite as Administrator "
                                  "to remove firewall rules.").arg(rc));
        }
        return rc == 0;
    };

    // refresh() is called from several long-lived Qt connections (buttons,
    // the auto-refresh timer, and per-row Unblock buttons rebuilt on every
    // refresh) that all outlive this function's stack frame -- held in a
    // shared_ptr and captured by value everywhere so nothing ever captures
    // a dangling reference to a local variable.
    auto refresh_fn = std::make_shared<std::function<void()>>();

    auto rebuildBlockedTable = [blocked_table, unblockIp, refresh_fn](const std::set<QString>& blocked) {
        blocked_table->setRowCount(0);
        for (const auto& ip : blocked) {
            const int row = blocked_table->rowCount();
            blocked_table->insertRow(row);
            auto* item = new QTableWidgetItem(ip);
            item->setForeground(QColor(0xFF, 0x5A, 0x6A));
            blocked_table->setItem(row, 0, item);
            auto* btn = new QPushButton(QString::fromUtf8("Unblock"), blocked_table);
            btn->setCursor(Qt::PointingHandCursor);
            btn->setStyleSheet(
                "QPushButton { background:#1C1108; border:1px solid #4ADE80; border-radius:6px;"
                "              color:#4ADE80; font-size:9pt; padding:3px 10px; }"
                "QPushButton:hover { background:#4ADE8030; }");
            QObject::connect(btn, &QPushButton::clicked, blocked_table, [ip, unblockIp, refresh_fn] {
                if (unblockIp(ip) && *refresh_fn) (*refresh_fn)();
            });
            blocked_table->setCellWidget(row, 1, btn);
        }
    };

    *refresh_fn = [table, status, rebuildBlockedTable] {
        const auto conns = Connections();
        const auto blocked = QueryBlockedIps();
        table->setRowCount(0);
        int ext = 0, blk = 0;
        for (const auto& c : conns) {
            const int row = table->rowCount();
            table->insertRow(row);
            table->setItem(row, 0, new QTableWidgetItem(c.proc));
            table->setItem(row, 1, new QTableWidgetItem(QString::number(c.pid)));
            table->setItem(row, 2, new QTableWidgetItem(c.local));
            auto* rem = new QTableWidgetItem(c.remote);
            rem->setData(Qt::UserRole, c.remoteIp);
            table->setItem(row, 3, rem);
            table->setItem(row, 4, new QTableWidgetItem(c.state));
            const bool is_blocked = !c.remoteIp.isEmpty() && blocked.count(c.remoteIp) > 0;
            auto* note = new QTableWidgetItem(is_blocked ? QString::fromUtf8("BLOCKED") : c.note);
            note->setForeground(is_blocked ? QColor(0xFF, 0x5A, 0x6A) : RiskColor(c.risk));
            table->setItem(row, 5, note);
            if (c.note == "External connection") ++ext;
            if (is_blocked) ++blk;
        }
        rebuildBlockedTable(blocked);
        status->setText(QString::fromUtf8("%1 connections, %2 external, %3 blocked.")
                            .arg(static_cast<int>(conns.size())).arg(ext).arg(blk));
    };

    QObject::connect(refresh_btn, &QPushButton::clicked, page, [refresh_fn] { if (*refresh_fn) (*refresh_fn)(); });
    QObject::connect(block_btn, &QPushButton::clicked, page, [page, table, refresh_fn] {
        const auto sel = table->selectionModel()->selectedRows();
        if (sel.isEmpty()) {
            QMessageBox::information(page, QString::fromUtf8("Firewall Pro"),
                QString::fromUtf8("Select a connection row first."));
            return;
        }
        auto* rem = table->item(sel.first().row(), 3);
        const QString ip = rem ? rem->data(Qt::UserRole).toString() : QString();
        if (ip.isEmpty() || ip == "*") {
            QMessageBox::information(page, QString::fromUtf8("Firewall Pro"),
                QString::fromUtf8("This row has no remote IP to block."));
            return;
        }
        const QStringList args{ "advfirewall", "firewall", "add", "rule",
            QString("name=%1").arg(RuleName(ip)), "dir=out", "action=block",
            QString("remoteip=%1").arg(ip) };
        const int rc = QProcess::execute("netsh", args);
        if (rc == 0) {
            if (*refresh_fn) (*refresh_fn)();
        } else {
            QMessageBox::warning(page, QString::fromUtf8("Could not block"),
                QString::fromUtf8("netsh failed (rc=%1). Run TeoAvSuite as Administrator "
                                  "to add firewall rules.").arg(rc));
        }
    });
    QObject::connect(unblock_btn, &QPushButton::clicked, page, [page, table, unblockIp, refresh_fn] {
        const auto sel = table->selectionModel()->selectedRows();
        if (sel.isEmpty()) {
            QMessageBox::information(page, QString::fromUtf8("Firewall Pro"),
                QString::fromUtf8("Select a connection row first (or use Unblock in the "
                                  "Blocked IPs list below for IPs with no live connection)."));
            return;
        }
        auto* rem = table->item(sel.first().row(), 3);
        const QString ip = rem ? rem->data(Qt::UserRole).toString() : QString();
        if (ip.isEmpty() || ip == "*") return;
        if (unblockIp(ip) && *refresh_fn) (*refresh_fn)();
    });

    // Auto-refresh so block/unblock state (and the connection list) stays
    // live without the user manually clicking Refresh every time.
    auto* auto_refresh = new QTimer(page);
    auto_refresh->setInterval(4000);
    QObject::connect(auto_refresh, &QTimer::timeout, page, [refresh_fn] { if (*refresh_fn) (*refresh_fn)(); });
    auto_refresh->start();

    (*refresh_fn)();
    return page;
}

} // namespace avdashboard
