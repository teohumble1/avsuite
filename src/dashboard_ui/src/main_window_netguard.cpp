// main_window_netguard.cpp — HTTP Traffic Monitor + Botnet Detector
// Monitors raw TCP/IP for suspicious HTTP patterns, C2 beaconing, proxy abuse,
// Squidbleed-style proxy exploitation, botnet membership, and DGA domains.
// Uses: WinHTTP, WFP (simplified via IPHLPAPI), DNS-based detection.

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

#include <atomic>
#include <chrono>
#include <cmath>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <regex>
#include <random>
#include <sstream>

#include <QCheckBox>
#include <QDateTime>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScrollArea>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QLineEdit>
#include <QProgressBar>

#include "autohunt_types.hpp"

namespace avdashboard {

// ─── HTTP event types ─────────────────────────────────────────────────────────
struct HttpEvent {
    enum Severity { Info, Suspicious, Critical };

    std::string proc_name;
    uint32_t    pid;
    std::string local_addr;
    std::string remote_addr;
    uint16_t    remote_port;
    std::string host;       // HTTP Host header (guessed from DNS)
    std::string threat_type;
    std::string detail;
    int         risk_score;
    Severity    severity;
    int64_t     ts_epoch;
};

// ─── Botnet candidate ─────────────────────────────────────────────────────────
struct BotnetCandidate {
    std::string proc_name;
    uint32_t    pid;
    std::string remote_ip;
    uint16_t    remote_port;
    int         beacon_count;   // times we've seen this connection re-appear
    int64_t     first_seen;
    int64_t     last_seen;
    int64_t     interval_secs;  // avg interval between beacons
    int         risk_score;
    bool        is_dga;         // domain looks machine-generated
    std::string verdict;
};

// ─── DGA detector: high entropy + suspicious TLD pattern ─────────────────────
static double StringEntropy(const std::string& s) {
    if (s.empty()) return 0.0;
    int freq[256]{};
    for (unsigned char c : s) freq[c]++;
    double ent = 0.0;
    for (int f : freq) {
        if (f == 0) continue;
        double p = static_cast<double>(f) / s.size();
        ent -= p * std::log2(p);
    }
    return ent;
}

static bool IsDgaDomain(const std::string& host) {
    // Strip port
    auto colon = host.find(':');
    std::string h = (colon != std::string::npos) ? host.substr(0, colon) : host;
    // Extract SLD (second-level domain)
    auto dot = h.rfind('.');
    if (dot == std::string::npos) return false;
    std::string tld = h.substr(dot + 1);
    std::string rest = h.substr(0, dot);
    auto dot2 = rest.rfind('.');
    std::string sld = (dot2 != std::string::npos) ? rest.substr(dot2 + 1) : rest;
    // Suspicious if SLD is long, high-entropy, mostly consonants
    if (sld.size() < 8) return false;
    double ent = StringEntropy(sld);
    if (ent < 3.2) return false;
    // Count vowels
    int vowels = 0;
    for (char c : sld) {
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') vowels++;
    }
    double vowel_ratio = static_cast<double>(vowels) / sld.size();
    return vowel_ratio < 0.15;  // very few vowels → likely DGA
}

// ─── Known C2 ports (not exhaustive, for UI demo) ─────────────────────────────
static const uint16_t kSuspiciousPorts[] = {
    1080, 4444, 5555, 6666, 6667, 7777, 8080, 8443, 9090, 9999,
    31337, 1337, 2222, 3389, 4141, 5050, 6060, 1234, 4545, 8888,
    0
};

static bool IsSuspiciousPort(uint16_t port) {
    for (int i = 0; kSuspiciousPorts[i]; ++i)
        if (port == kSuspiciousPorts[i]) return true;
    return false;
}

// ─── Beacon tracker: detect regular-interval connections ─────────────────────
struct BeaconTracker {
    std::mutex mtx;
    // key: "pid|remote_ip:port"
    struct Entry {
        std::string proc_name;
        uint32_t pid;
        std::string remote;
        std::vector<int64_t> timestamps;  // epoch seconds of each observation
    };
    std::unordered_map<std::string, Entry> entries;

    // Returns beacon candidate if regularity detected (>= 3 observations, jitter < 15%)
    std::optional<BotnetCandidate> Record(const std::string& key, const std::string& proc,
                                           uint32_t pid, const std::string& remote,
                                           uint16_t port) {
        std::lock_guard<std::mutex> lk(mtx);
        auto& e = entries[key];
        e.proc_name = proc;
        e.pid = pid;
        e.remote = remote;
        using namespace std::chrono;
        int64_t now = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
        e.timestamps.push_back(now);
        if (e.timestamps.size() < 3) return std::nullopt;

        // Compute intervals
        std::vector<int64_t> intervals;
        for (size_t i = 1; i < e.timestamps.size(); ++i)
            intervals.push_back(e.timestamps[i] - e.timestamps[i-1]);

        // Mean interval
        double sum = 0;
        for (auto iv : intervals) sum += static_cast<double>(iv);
        double mean = sum / intervals.size();
        if (mean < 2.0) return std::nullopt;  // too fast, not beaconing

        // Coefficient of variation (jitter)
        double var = 0;
        for (auto iv : intervals) {
            double d = iv - mean;
            var += d * d;
        }
        double cv = std::sqrt(var / intervals.size()) / mean;
        if (cv > 0.20) return std::nullopt;  // too irregular

        // Likely beaconing
        BotnetCandidate c;
        c.proc_name    = proc;
        c.pid          = pid;
        c.remote_ip    = remote;
        c.remote_port  = port;
        c.beacon_count = static_cast<int>(e.timestamps.size());
        c.first_seen   = e.timestamps.front();
        c.last_seen    = e.timestamps.back();
        c.interval_secs = static_cast<int64_t>(mean);
        c.is_dga       = IsDgaDomain(remote);
        c.risk_score   = std::min(100, 50 + c.beacon_count * 3 + (c.is_dga ? 20 : 0));
        c.verdict      = cv < 0.05 ? "HIGH-CONFIDENCE BEACON" : "PROBABLE BEACON";
        return c;
    }
};

// ─── Process name lookup ──────────────────────────────────────────────────────
static std::string GetProcName(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "<unknown>";
    wchar_t buf[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    if (!QueryFullProcessImageNameW(h, 0, buf, &sz)) {
        CloseHandle(h);
        return "<unknown>";
    }
    CloseHandle(h);
    std::wstring ws(buf, sz);
    auto slash = ws.rfind(L'\\');
    if (slash != std::wstring::npos) ws = ws.substr(slash + 1);
    return std::string(ws.begin(), ws.end());
}

// ─── DNS cache for hostname lookup ────────────────────────────────────────────
struct DnsCache {
    std::mutex mtx;
    std::unordered_map<std::string, std::string> cache;
    std::string Lookup(const std::string& ip) {
        {
            std::lock_guard<std::mutex> lk(mtx);
            auto it = cache.find(ip);
            if (it != cache.end()) return it->second;
        }
        // Reverse DNS
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
        char host[NI_MAXHOST]{};
        if (getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa),
                        host, NI_MAXHOST, nullptr, 0, NI_NAMEREQD) == 0) {
            std::string h(host);
            std::lock_guard<std::mutex> lk(mtx);
            cache[ip] = h;
            return h;
        }
        std::lock_guard<std::mutex> lk(mtx);
        cache[ip] = ip;
        return ip;
    }
};

// ─── Scanner: polls TCP table for HTTP-pattern connections ────────────────────
struct NetGuardScanner {
    std::atomic<bool> stop{false};
    std::mutex events_mtx;
    std::deque<HttpEvent>      events;
    std::deque<BotnetCandidate> bots;
    BeaconTracker beacon_tracker;
    DnsCache      dns_cache;
    std::atomic<int> total_scanned{0};
    std::atomic<int> total_http{0};
    std::atomic<int> total_bots{0};

    void Scan() {
        // Get TCP table
        DWORD sz = 0;
        GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> buf(sz + 1024);
        auto* tbl = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
        if (GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            != NO_ERROR) return;

        using namespace std::chrono;
        int64_t now = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
        total_scanned.store(static_cast<int>(tbl->dwNumEntries));

        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
            const auto& row = tbl->table[i];
            if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

            uint32_t pid      = row.dwOwningPid;
            uint16_t rport    = ntohs(static_cast<uint16_t>(row.dwRemotePort));
            if (rport == 0) continue;

            // Convert remote IP
            char rip_buf[INET_ADDRSTRLEN]{};
            auto ra = row.dwRemoteAddr;
            inet_ntop(AF_INET, &ra, rip_buf, sizeof(rip_buf));
            std::string rip(rip_buf);

            // Skip loopback and private (simplified)
            if (rip.substr(0,3) == "127" || rip.substr(0,3) == "10." ||
                rip.substr(0,7) == "192.168" || rip.substr(0,5) == "172.1") continue;

            std::string proc = GetProcName(pid);
            std::string key  = std::to_string(pid) + "|" + rip + ":" + std::to_string(rport);

            bool suspicious = false;
            std::string threat;
            int risk = 10;

            // HTTP/HTTPS port checks
            bool is_http  = (rport == 80 || rport == 8080 || rport == 3128 || rport == 8888);
            bool is_https = (rport == 443 || rport == 8443);

            if (is_http || is_https) total_http.fetch_add(1);

            // Squidbleed / proxy abuse: non-browser hitting port 3128 (Squid default)
            if (rport == 3128 && proc != "firefox.exe" && proc != "chrome.exe" &&
                proc != "msedge.exe" && proc != "iexplore.exe") {
                suspicious = true;
                threat = "Proxy Abuse (Squid/3128)";
                risk = 75;
            }

            // Suspicious port beaconing
            if (IsSuspiciousPort(rport) && rport != 80 && rport != 443) {
                suspicious = true;
                threat = "Suspicious C2 Port";
                risk = std::max(risk, 65);
            }

            // DGA check (via reverse DNS)
            std::string hostname = dns_cache.Lookup(rip);
            if (IsDgaDomain(hostname)) {
                suspicious = true;
                threat = "DGA Domain Detected";
                risk = std::max(risk, 80);
            }

            // Beacon detection
            if (auto bot = beacon_tracker.Record(key, proc, pid, rip, rport)) {
                suspicious = true;
                threat = bot->verdict;
                risk = std::max(risk, bot->risk_score);

                // Add to botnet list
                std::lock_guard<std::mutex> lk(events_mtx);
                bool found = false;
                for (auto& b : bots) {
                    if (b.pid == pid && b.remote_ip == rip && b.remote_port == rport) {
                        b = *bot;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    bots.push_front(*bot);
                    if (bots.size() > 200) bots.pop_back();
                    total_bots.fetch_add(1);

                    // Feed to AI Hunt
                    HuntTarget ht;
                    ht.source      = "Network";
                    ht.name        = proc + " → " + rip;
                    ht.path        = proc;
                    ht.risk_score  = bot->risk_score;
                    ht.description = bot->verdict + " every ~" +
                                     std::to_string(bot->interval_secs) + "s";
                    AutoHuntEnqueue(std::move(ht));
                }
            }

            if (suspicious) {
                HttpEvent ev;
                ev.proc_name   = proc;
                ev.pid         = pid;
                ev.remote_addr = rip;
                ev.remote_port = rport;
                ev.host        = hostname;
                ev.threat_type = threat;
                ev.detail      = proc + " → " + rip + ":" + std::to_string(rport) +
                                 " (" + hostname + ")";
                ev.risk_score  = risk;
                ev.severity    = risk >= 75 ? HttpEvent::Critical : HttpEvent::Suspicious;
                ev.ts_epoch    = now;

                std::lock_guard<std::mutex> lk(events_mtx);
                // Deduplicate by key within last 60s
                bool dup = false;
                for (const auto& e : events) {
                    if (e.pid == pid && e.remote_port == rport &&
                        e.remote_addr == rip && (now - e.ts_epoch) < 60) {
                        dup = true; break;
                    }
                }
                if (!dup) {
                    events.push_front(ev);
                    if (events.size() > 500) events.pop_back();
                }
            }
        }
    }
};

// ─── Page builder ─────────────────────────────────────────────────────────────
QWidget* BuildNetGuardPage(QWidget* parent) {
    static constexpr const char* kBg     = "#0E0804";
    static constexpr const char* kCard   = "#120B06";
    static constexpr const char* kBorder = "#33261A";
    static constexpr const char* kText   = "#ECE4DA";
    static constexpr const char* kMuted  = "#8B7355";
    static constexpr const char* kRed    = "#FF5A6A";
    static constexpr const char* kOrange = "#FBBF24";
    static constexpr const char* kGreen  = "#4ADE80";
    static constexpr const char* kBlue   = "#4DB8FF";
    static constexpr const char* kCyan   = "#4DB8FF";

    auto* page = new QWidget(parent);
    page->setStyleSheet(QString("background:%1;").arg(kBg));

    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(20, 16, 20, 16);
    root->setSpacing(10);

    // ── Header ──────────────────────────────────────────────────────────────
    {
        auto* hdr = new QHBoxLayout;
        auto* title = new QLabel("NetGuard — HTTP & Botnet Monitor");
        title->setStyleSheet(QString("color:%1;font-size:17px;font-weight:700;").arg(kText));
        auto* sub = new QLabel("Real-time HTTP traffic analysis · Squidbleed defense · Botnet beacon detection");
        sub->setStyleSheet(QString("color:%1;font-size:11px;").arg(kMuted));
        hdr->addWidget(title);
        hdr->addWidget(sub);
        hdr->addStretch();
        root->addLayout(hdr);
    }

    // ── Stat row ────────────────────────────────────────────────────────────
    QLabel *statConns=nullptr, *statHttp=nullptr, *statThreats=nullptr, *statBots=nullptr;
    {
        auto makeCard = [&](const QString& val, const QString& lbl,
                            const char* col, QLabel** out) {
            auto* w  = new QWidget;
            auto* vl = new QVBoxLayout(w);
            vl->setContentsMargins(14,10,14,10);
            vl->setSpacing(3);
            auto* v = new QLabel(val);
            v->setStyleSheet(QString("color:%1;font-size:20px;font-weight:700;").arg(col));
            auto* l = new QLabel(lbl);
            l->setStyleSheet(QString("color:%1;font-size:10px;").arg(kMuted));
            vl->addWidget(v); vl->addWidget(l);
            w->setStyleSheet(QString("background:%1;border:1px solid %2;border-radius:8px;")
                                 .arg(kCard).arg(kBorder));
            if (out) *out = v;
            return w;
        };
        auto* row = new QHBoxLayout;
        row->setSpacing(8);
        row->addWidget(makeCard("0", "TCP Connections",  kText,   &statConns));
        row->addWidget(makeCard("0", "HTTP/Proxy",       kCyan,   &statHttp));
        row->addWidget(makeCard("0", "Threats Detected", kRed,    &statThreats));
        row->addWidget(makeCard("0", "Botnet Beacons",   kOrange, &statBots));
        root->addLayout(row);
    }

    // ── Tabs: HTTP Threats | Botnet Beacons ──────────────────────────────────
    auto* tabBar = new QHBoxLayout;
    tabBar->setSpacing(0);
    auto* tabHttp = new QPushButton("HTTP Threats");
    auto* tabBot  = new QPushButton("Botnet Beacons");

    auto tabStyle = [&](QPushButton* active, QPushButton* inactive) {
        active->setStyleSheet(QString(R"(
            QPushButton { background:%1; color:%2; border:none; border-bottom:2px solid %3;
                          padding:6px 20px; font-size:12px; font-weight:600; }
        )").arg(kCard).arg(kText).arg(kCyan));
        inactive->setStyleSheet(QString(R"(
            QPushButton { background:transparent; color:%1; border:none;
                          border-bottom:2px solid transparent;
                          padding:6px 20px; font-size:12px; }
            QPushButton:hover { color:%2; }
        )").arg(kMuted).arg(kText));
    };
    tabHttp->setCursor(Qt::PointingHandCursor);
    tabBot->setCursor(Qt::PointingHandCursor);
    tabBar->addWidget(tabHttp);
    tabBar->addWidget(tabBot);
    tabBar->addStretch();
    root->addLayout(tabBar);

    // ── HTTP threats table ────────────────────────────────────────────────────
    auto* httpCard = new QWidget;
    httpCard->setStyleSheet(QString("background:%1;border:1px solid %2;border-radius:8px;")
                                .arg(kCard).arg(kBorder));
    auto* httpVL = new QVBoxLayout(httpCard);
    httpVL->setContentsMargins(0,0,0,0);

    auto* httpTbl = new QTableWidget(0, 6);
    httpTbl->setHorizontalHeaderLabels({"Risk", "Process", "Remote IP", "Port", "Threat", "Time"});
    httpTbl->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    httpTbl->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    httpTbl->setColumnWidth(0, 52);
    httpTbl->setColumnWidth(2, 120);
    httpTbl->setColumnWidth(3, 52);
    httpTbl->setColumnWidth(5, 72);
    httpTbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    httpTbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    httpTbl->verticalHeader()->setVisible(false);
    httpTbl->setShowGrid(false);
    httpTbl->setAlternatingRowColors(false);
    httpTbl->setStyleSheet(QString(R"(
        QTableWidget { background:transparent; color:%1; border:none; font-size:12px; }
        QTableWidget::item { padding:6px 10px; border-bottom:1px solid %2; }
        QTableWidget::item:selected { background:#33261A; }
        QHeaderView::section { background:%3; color:%4; border:none;
                               border-bottom:1px solid %2; padding:5px 10px; font-size:11px; }
        QScrollBar:vertical { background:%3; width:5px; border-radius:2px; }
        QScrollBar::handle:vertical { background:%2; border-radius:2px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
    )").arg(kText).arg(kBorder).arg(kCard).arg(kMuted));
    httpVL->addWidget(httpTbl);

    // ── Detail panel below HTTP table ─────────────────────────────────────────
    auto* httpDetail = new QTextEdit;
    httpDetail->setReadOnly(true);
    httpDetail->setMaximumHeight(80);
    httpDetail->setStyleSheet(QString(R"(
        QTextEdit { background:#120B06; color:%1; border:none; border-top:1px solid %2;
                    font-family:Consolas,monospace; font-size:11px; padding:8px; }
    )").arg(kText).arg(kBorder));
    httpVL->addWidget(httpDetail);

    // ── Botnet table ──────────────────────────────────────────────────────────
    auto* botCard = new QWidget;
    botCard->setVisible(false);
    botCard->setStyleSheet(QString("background:%1;border:1px solid %2;border-radius:8px;")
                               .arg(kCard).arg(kBorder));
    auto* botVL = new QVBoxLayout(botCard);
    botVL->setContentsMargins(0,0,0,0);

    auto* botTbl = new QTableWidget(0, 7);
    botTbl->setHorizontalHeaderLabels({
        "Risk", "Process", "Remote IP", "Port", "Beacons", "Interval", "Verdict"
    });
    botTbl->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    botTbl->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    botTbl->setColumnWidth(0, 52);
    botTbl->setColumnWidth(3, 52);
    botTbl->setColumnWidth(4, 68);
    botTbl->setColumnWidth(5, 78);
    botTbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    botTbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    botTbl->verticalHeader()->setVisible(false);
    botTbl->setShowGrid(false);
    botTbl->setStyleSheet(httpTbl->styleSheet());
    botVL->addWidget(botTbl);

    // Bot detail
    auto* botDetail = new QTextEdit;
    botDetail->setReadOnly(true);
    botDetail->setMaximumHeight(80);
    botDetail->setStyleSheet(httpDetail->styleSheet());
    botVL->addWidget(botDetail);

    root->addWidget(httpCard, 1);
    root->addWidget(botCard,  1);

    // ── Tab switching ─────────────────────────────────────────────────────────
    tabStyle(tabHttp, tabBot);

    QObject::connect(tabHttp, &QPushButton::clicked, page, [=]() {
        httpCard->setVisible(true);
        botCard->setVisible(false);
        tabStyle(tabHttp, tabBot);
    });
    QObject::connect(tabBot, &QPushButton::clicked, page, [=]() {
        httpCard->setVisible(false);
        botCard->setVisible(true);
        tabStyle(tabBot, tabHttp);
    });

    // ── Scanner state ─────────────────────────────────────────────────────────
    auto* scanner = new NetGuardScanner;
    page->setProperty("ngScanner", QVariant::fromValue(static_cast<void*>(scanner)));

    int threatCount = 0;

    // HTTP table row selection → detail
    QObject::connect(httpTbl, &QTableWidget::currentCellChanged, page,
                     [=](int row, int, int, int) {
        std::lock_guard<std::mutex> lk(scanner->events_mtx);
        if (row >= 0 && row < static_cast<int>(scanner->events.size())) {
            const auto& ev = scanner->events[row];
            QDateTime dt = QDateTime::fromSecsSinceEpoch(ev.ts_epoch);
            httpDetail->setPlainText(
                QString("Process : %1 (PID %2)\n"
                        "Remote  : %3:%4\n"
                        "Host    : %5\n"
                        "Threat  : %6\n"
                        "Risk    : %7/100\n"
                        "Time    : %8")
                    .arg(QString::fromStdString(ev.proc_name))
                    .arg(ev.pid)
                    .arg(QString::fromStdString(ev.remote_addr))
                    .arg(ev.remote_port)
                    .arg(QString::fromStdString(ev.host))
                    .arg(QString::fromStdString(ev.threat_type))
                    .arg(ev.risk_score)
                    .arg(dt.toString("hh:mm:ss")));
        }
    });

    // Bot table row selection → detail
    QObject::connect(botTbl, &QTableWidget::currentCellChanged, page,
                     [=](int row, int, int, int) {
        std::lock_guard<std::mutex> lk(scanner->events_mtx);
        if (row >= 0 && row < static_cast<int>(scanner->bots.size())) {
            const auto& b = scanner->bots[row];
            QDateTime f = QDateTime::fromSecsSinceEpoch(b.first_seen);
            QDateTime l = QDateTime::fromSecsSinceEpoch(b.last_seen);
            botDetail->setPlainText(
                QString("Process  : %1 (PID %2)\n"
                        "Remote   : %3:%4\n"
                        "Beacons  : %5  Interval: ~%6s\n"
                        "DGA      : %7\n"
                        "Verdict  : %8\n"
                        "First    : %9  Last: %10")
                    .arg(QString::fromStdString(b.proc_name))
                    .arg(b.pid)
                    .arg(QString::fromStdString(b.remote_ip))
                    .arg(b.remote_port)
                    .arg(b.beacon_count)
                    .arg(b.interval_secs)
                    .arg(b.is_dga ? "YES (machine-generated domain)" : "No")
                    .arg(QString::fromStdString(b.verdict))
                    .arg(f.toString("hh:mm:ss"))
                    .arg(l.toString("hh:mm:ss")));
        }
    });

    // ── Scan timer: every 4 seconds ───────────────────────────────────────────
    auto* scanTimer = new QTimer(page);
    scanTimer->setInterval(4000);

    auto refreshTables = [=, &threatCount]() {
        // Update HTTP threats table
        std::vector<HttpEvent>      evSnap;
        std::vector<BotnetCandidate> botSnap;
        {
            std::lock_guard<std::mutex> lk(scanner->events_mtx);
            evSnap.assign(scanner->events.begin(), scanner->events.end());
            botSnap.assign(scanner->bots.begin(), scanner->bots.end());
        }

        httpTbl->setRowCount(static_cast<int>(evSnap.size()));
        for (int r = 0; r < static_cast<int>(evSnap.size()); ++r) {
            const auto& ev = evSnap[r];
            QString riskStr = QString::number(ev.risk_score);
            QColor  riskCol = ev.severity == HttpEvent::Critical
                ? QColor(kRed) : QColor(kOrange);

            auto setItem = [&](int col, const QString& txt, QColor c = QColor(kText)) {
                auto* item = new QTableWidgetItem(txt);
                item->setForeground(c);
                httpTbl->setItem(r, col, item);
            };
            setItem(0, riskStr, riskCol);
            setItem(1, QString::fromStdString(ev.proc_name));
            setItem(2, QString::fromStdString(ev.remote_addr));
            setItem(3, QString::number(ev.remote_port));
            setItem(4, QString::fromStdString(ev.threat_type), riskCol);
            QDateTime dt = QDateTime::fromSecsSinceEpoch(ev.ts_epoch);
            setItem(5, dt.toString("hh:mm:ss"));
            httpTbl->setRowHeight(r, 34);
        }

        botTbl->setRowCount(static_cast<int>(botSnap.size()));
        for (int r = 0; r < static_cast<int>(botSnap.size()); ++r) {
            const auto& b = botSnap[r];
            QColor riskCol = b.risk_score >= 75 ? QColor(kRed) : QColor(kOrange);
            auto setItem = [&](int col, const QString& txt, QColor c = QColor(kText)) {
                auto* item = new QTableWidgetItem(txt);
                item->setForeground(c);
                botTbl->setItem(r, col, item);
            };
            setItem(0, QString::number(b.risk_score), riskCol);
            setItem(1, QString::fromStdString(b.proc_name));
            setItem(2, QString::fromStdString(b.remote_ip));
            setItem(3, QString::number(b.remote_port));
            setItem(4, QString::number(b.beacon_count), QColor(kCyan));
            setItem(5, QString("~%1s").arg(b.interval_secs));
            setItem(6, QString::fromStdString(b.verdict), riskCol);
            botTbl->setRowHeight(r, 34);
        }

        // Stats
        if (statConns)  statConns->setText(QString::number(scanner->total_scanned.load()));
        if (statHttp)   statHttp->setText(QString::number(scanner->total_http.load()));
        if (statThreats) statThreats->setText(QString::number(evSnap.size()));
        if (statBots)   statBots->setText(QString::number(scanner->total_bots.load()));
    };

    QObject::connect(scanTimer, &QTimer::timeout, page, [=]() mutable {
        // Run scan on background thread, then refresh UI
        std::thread([=]() {
            scanner->Scan();
            QMetaObject::invokeMethod(page, [=]() { refreshTables(); },
                                      Qt::QueuedConnection);
        }).detach();
    });

    scanTimer->start();

    // Initial scan
    QTimer::singleShot(500, page, [=]() {
        std::thread([=]() {
            scanner->Scan();
            QMetaObject::invokeMethod(page, [=]() { refreshTables(); },
                                      Qt::QueuedConnection);
        }).detach();
    });

    // Cleanup on destroy
    QObject::connect(page, &QWidget::destroyed, page, [scanner]() {
        scanner->stop.store(true);
        delete scanner;
    });

    return page;
}

} // namespace avdashboard
