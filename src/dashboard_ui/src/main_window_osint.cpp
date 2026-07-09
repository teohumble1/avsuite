// main_window_osint.cpp — OSINT Hub: IOC lookup + basic target recon.
//
// Paste a target (file hash, IP, domain, or URL) and get:
//   - IOC reputation via VirusTotal (hash/IP/domain endpoints, needs API key)
//   - DNS: forward resolution for a domain, reverse lookup for an IP
//   - A bounded TCP connect-scan of ~20 well-known ports against the
//     resolved IP, so you can see what's actually listening
//
// Defensive/educational recon tool: only scans a target the user explicitly
// pastes in, and only a small fixed port list (not a general-purpose
// scanner). ASCII labels (MSVC builds without /utf-8).

#include "main_window.hpp"
#include "av_quit_guard.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
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
#pragma comment(lib, "ws2_32.lib")

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace avdashboard {
namespace {

struct PortInfo { int port; const char* service; };
const std::vector<PortInfo>& CommonPorts() {
    static const std::vector<PortInfo> ports = {
        {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
        {80,"HTTP"},{110,"POP3"},{135,"RPC"},{139,"NetBIOS"},{143,"IMAP"},
        {443,"HTTPS"},{445,"SMB"},{993,"IMAPS"},{995,"POP3S"},{1433,"MSSQL"},
        {3306,"MySQL"},{3389,"RDP"},{5900,"VNC"},{8080,"HTTP-alt"},{8443,"HTTPS-alt"},
    };
    return ports;
}

// Non-blocking connect with a short timeout -- a plain blocking connect()
// can hang for the OS default timeout (tens of seconds) per closed port.
bool TryConnect(const std::string& ip, int port, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;

    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode); // non-blocking

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        closesocket(s);
        return false;
    }

    bool open = false;
    int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        open = true;
    } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set wfds; FD_ZERO(&wfds); FD_SET(s, &wfds);
        timeval tv{}; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (select(0, nullptr, &wfds, nullptr, &tv) > 0 && FD_ISSET(s, &wfds)) {
            int err = 0; int len = sizeof(err);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) == 0 && err == 0) {
                open = true;
            }
        }
    }
    closesocket(s);
    return open;
}

// Forward-resolves a hostname to its first IPv4 address. Empty on failure.
std::string ResolveToIp(const std::string& host) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return {};
    char buf[INET_ADDRSTRLEN] = {};
    auto* sin = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
    freeaddrinfo(res);
    return buf;
}

// Reverse-resolves an IPv4 address to a hostname. Empty if none (common --
// most IPs have no PTR record).
std::string ReverseDns(const std::string& ip) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) return {};
    char host[NI_MAXHOST] = {};
    if (getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
                     host, sizeof(host), nullptr, 0, NI_NAMEREQD) != 0) {
        return {};
    }
    return host;
}

bool LooksLikeHash(const QString& s) {
    if (s.size() != 32 && s.size() != 40 && s.size() != 64) return false;
    static const QRegularExpression hex("^[A-Fa-f0-9]+$");
    return hex.match(s).hasMatch();
}

bool LooksLikeIpv4(const QString& s) {
    static const QRegularExpression ip(
        "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    const auto m = ip.match(s);
    if (!m.hasMatch()) return false;
    for (int i = 1; i <= 4; ++i) {
        if (m.captured(i).toInt() > 255) return false;
    }
    return true;
}

// Strips a URL down to its host, so pasting a full URL still works.
QString ExtractHost(QString s) {
    s = s.trimmed();
    s.remove(QRegularExpression("^[a-zA-Z]+://"));
    const int slash = s.indexOf('/');
    if (slash >= 0) s = s.left(slash);
    const int colon = s.indexOf(':');
    if (colon >= 0) s = s.left(colon);
    return s;
}

} // namespace

QWidget* BuildOsintPage(QWidget* parent) {
    auto* win = qobject_cast<MainWindow*>(parent);
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(12);

    auto* title = new QLabel(QString::fromUtf8("OSINT Hub"), page);
    title->setStyleSheet("color:#E8E8E8; font-size:16pt; font-weight:800; background:transparent;");
    root->addWidget(title);
    auto* sub = new QLabel(QString::fromUtf8(
        "Paste a file hash, IP, domain, or URL. Looks up reputation on VirusTotal "
        "(needs API key in Settings), resolves DNS, and probes ~20 well-known TCP "
        "ports on the resolved IP so you can see what's actually listening."), page);
    sub->setStyleSheet("color:#8B8B8B; font-size:9pt; background:transparent;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(10);
    auto* input = new QLineEdit(page);
    input->setPlaceholderText(QString::fromUtf8("hash / IP / domain / URL..."));
    input->setStyleSheet(
        "QLineEdit { background:#1C1008; color:#E8E8E8; border:1px solid rgba(255,122,0,40);"
        " border-radius:8px; padding:9px 12px; font-size:10pt; }"
        "QLineEdit:focus { border-color:#FF7A00; }");
    ctl->addWidget(input, 1);
    auto* lookup_btn = new QPushButton(QString::fromUtf8("Lookup"), page);
    lookup_btn->setCursor(Qt::PointingHandCursor);
    lookup_btn->setStyleSheet(
        "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #CC5500);"
        " border:none; border-radius:8px; color:#fff; font-size:10.5pt; font-weight:700; padding:9px 26px; }"
        "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9030,stop:1 #DD6600); }"
        "QPushButton:disabled { background:#2A1F14; color:#8B8B8B; }");
    ctl->addWidget(lookup_btn);
    root->addLayout(ctl);

    auto* status = new QLabel(QString::fromUtf8("Idle."), page);
    status->setStyleSheet("color:#8B8B8B; font-size:9pt; background:transparent;");
    root->addWidget(status);

    auto* results = new QPlainTextEdit(page);
    results->setReadOnly(true);
    results->setStyleSheet(
        "QPlainTextEdit { background:#1C1008; color:#E8E8E8; font-family:Consolas,monospace;"
        " font-size:9.5pt; border:1px solid #2A1F14; border-radius:10px; padding:10px; }");
    results->setMaximumBlockCount(500);
    results->setFixedHeight(160);
    root->addWidget(results);

    auto* port_lbl = new QLabel(QString::fromUtf8("Open ports"), page);
    port_lbl->setStyleSheet("color:#8B8B8B; font-size:9pt; font-weight:700; background:transparent;");
    root->addWidget(port_lbl);

    auto* table = new QTableWidget(0, 2, page);
    table->setHorizontalHeaderLabels({"Port", "Service"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);
    table->setStyleSheet(
        "QTableWidget { background:#1C1008; color:#E8E8E8; font-size:9.5pt; border:1px solid #2A1F14;"
        " border-radius:10px; gridline-color:#2A1F14; }"
        "QTableWidget::item { padding:5px 8px; }"
        "QHeaderView::section { background:#130D07; color:#8B8B8B; font-size:9pt; font-weight:700;"
        " padding:6px; border:none; border-bottom:1px solid #2A1F14; }");
    {
        auto* h = table->horizontalHeader();
        h->setStretchLastSection(true);
        h->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    }
    root->addWidget(table, 1);

    ArmQuitGuard(page);
    auto scanning = std::make_shared<std::atomic<bool>>(false);

    QObject::connect(lookup_btn, &QPushButton::clicked, page,
            [page, input, lookup_btn, status, results, table, scanning, win]() {
        if (!win || scanning->load()) return;
        const QString raw = input->text().trimmed();
        if (raw.isEmpty()) return;

        scanning->store(true);
        lookup_btn->setEnabled(false);
        results->clear();
        table->setRowCount(0);
        status->setText(QString::fromUtf8("Resolving & querying..."));

        std::thread([raw, status, results, table, scanning, win]() {
            WSADATA wsaData;
            const bool ws_ok = WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;

            QString kind, target;
            if (LooksLikeHash(raw)) { kind = "hash"; target = raw; }
            else if (LooksLikeIpv4(raw)) { kind = "ip"; target = raw; }
            else { kind = "domain"; target = ExtractHost(raw); }

            QStringList lines;
            std::string scan_ip;

            if (kind == "hash") {
                lines << QString::fromUtf8("=== VirusTotal (hash) ===");
                lines << win->LookupVtIoc("hash", target);
            } else if (kind == "ip") {
                scan_ip = target.toStdString();
                const std::string ptr = ReverseDns(scan_ip);
                lines << QString::fromUtf8("=== DNS ===");
                lines << (ptr.empty()
                    ? QString::fromUtf8("Reverse DNS: (no PTR record)")
                    : QString::fromUtf8("Reverse DNS: ") + QString::fromStdString(ptr));
                lines << QString::fromUtf8("\n=== VirusTotal (IP) ===");
                lines << win->LookupVtIoc("ip", target);
            } else {
                lines << QString::fromUtf8("=== DNS ===");
                scan_ip = ResolveToIp(target.toStdString());
                lines << (scan_ip.empty()
                    ? QString::fromUtf8("Forward resolve: FAILED")
                    : QString::fromUtf8("Forward resolve: ") + QString::fromStdString(scan_ip));
                lines << QString::fromUtf8("\n=== VirusTotal (domain) ===");
                lines << win->LookupVtIoc("domain", target);
            }

            std::vector<PortInfo> open_ports;
            if (!scan_ip.empty()) {
                for (const auto& p : CommonPorts()) {
                    if (!scanning->load() || AppQuitting().load()) break;
                    if (TryConnect(scan_ip, p.port, 400)) open_ports.push_back(p);
                }
            }

            if (ws_ok) WSACleanup();
            if (AppQuitting().load()) return;

            const QString text = lines.join("\n");
            QMetaObject::invokeMethod(status, [status, results, table, scanning, text, open_ports, kind]() {
                results->setPlainText(text);
                for (const auto& p : open_ports) {
                    const int row = table->rowCount();
                    table->insertRow(row);
                    table->setItem(row, 0, new QTableWidgetItem(QString::number(p.port)));
                    table->setItem(row, 1, new QTableWidgetItem(QString::fromUtf8(p.service)));
                }
                status->setText(kind == "hash"
                    ? QString::fromUtf8("Done.")
                    : QString::fromUtf8("Done. %1 open port(s) found.").arg(open_ports.size()));
                scanning->store(false);
            }, Qt::QueuedConnection);
        }).detach();
    });

    auto* sync = new QTimer(page);
    sync->setInterval(300);
    QObject::connect(sync, &QTimer::timeout, lookup_btn, [lookup_btn, scanning]() {
        lookup_btn->setEnabled(!scanning->load());
    });
    sync->start();

    return page;
}

} // namespace avdashboard
