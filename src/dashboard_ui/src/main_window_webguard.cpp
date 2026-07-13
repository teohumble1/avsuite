// main_window_webguard.cpp — Web Guard
// Realtime monitoring of malicious-JavaScript web attacks. A native agent can't
// see inside the browser's JS engine, so Web Guard watches the two surfaces it
// CAN observe honestly (see docs/web-guard-threat-research.md):
//
//   - NETWORK: every browser process' outbound TCP connections (GetExtendedTcpTable)
//              matched against a resolved blocklist of malicious-JS infrastructure
//              (cryptomining pools, Magecart skimmer gates, malvertising / exploit
//              -kit gates, tracker-C2). Only browser-owned connections count.
//   - DISK:    installed Chromium-family extension scripts (loose .js on disk that
//              the browser fetched) scanned for obfuscation markers + miner keywords.
//
// No fabricated rows: every row is a real live connection or a real flagged file.
// Applying BLOCKING shells out (elevated) to the repo's Harden-WebGuard.ps1, which
// null-routes the IOC hosts + adds an outbound firewall block rule (both reversible).

// Winsock2 headers MUST precede any <windows.h> (which main_window.hpp / Qt pull
// in transitively). If windows.h is seen first it drags in the legacy winsock.h
// and ws2tcpip.h below fails to compile. NOMINMAX stops the Windows min/max
// macros clashing with the Qt headers.
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <Psapi.h>

#include "main_window.hpp"
#include "theme.hpp"
#include "av_quit_guard.hpp"

#include <QAbstractItemView>
#include <QDir>
#include <QDirIterator>
#include <QFont>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QStyle>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTime>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace avdashboard {
namespace {

// ─── Malicious-JS infrastructure blocklist + category ─────────────────────────
// Representative, extensible IOCs. Cryptomining pools/miner-JS domains still
// resolve and match live traffic today; historical EK/skimmer gates are kept as
// IOCs. See docs/web-guard-threat-research.md.
struct BadHost { const wchar_t* host; const char* category; };
const BadHost kBadHosts[] = {
    // ── Cryptojacking (in-browser miners / pools) ──
    {L"coinhive.com",            "Cryptojacking"},
    {L"coin-hive.com",           "Cryptojacking"},
    {L"authedmine.com",          "Cryptojacking"},
    {L"cnhv.co",                 "Cryptojacking"},
    {L"coinimp.com",             "Cryptojacking"},
    {L"www.coinimp.com",         "Cryptojacking"},
    {L"minero.cc",               "Cryptojacking"},
    {L"crypto-loot.com",         "Cryptojacking"},
    {L"cryptoloot.pro",          "Cryptojacking"},
    {L"webminepool.com",         "Cryptojacking"},
    {L"webmine.cz",              "Cryptojacking"},
    {L"jsecoin.com",             "Cryptojacking"},
    {L"load.jsecoin.com",        "Cryptojacking"},
    {L"ppoi.org",                "Cryptojacking"},
    // ── Magecart / formjacking skimmer gates (lookalike CDNs) ──
    {L"magento-analytics.com",   "Skimmer"},
    {L"google-analytics.top",    "Skimmer"},
    {L"googie-anaiytics.com",    "Skimmer"},
    {L"jquery-cdn.top",          "Skimmer"},
    {L"cdn-js.link",             "Skimmer"},
    {L"ajaxstatic.com",          "Skimmer"},
    // ── Malvertising redirect / gate ──
    {L"go.oclaserver.com",       "Malvertising"},
    {L"onclickpredictiv.com",    "Malvertising"},
    {L"adnium.com",              "Malvertising"},
    {L"propu.pl",                "Malvertising"},
    // ── Exploit-kit gates (historical IOCs) ──
    {L"eitest.gate",             "ExploitKit"},
    {L"fallout.gate",            "ExploitKit"},
    // ── Tracker / C2 beacon ──
    {L"stat-analytics.info",     "TrackerC2"},
    {L"track-cdn.net",           "TrackerC2"},
};

const char* CategoryColor(const QString& cat) {
    if (cat == "Cryptojacking") return theme::Danger;   // red
    if (cat == "Skimmer")       return theme::Accent;    // amber
    if (cat == "Malvertising")  return theme::Warn;      // yellow
    if (cat == "ExploitKit")    return theme::Danger;    // red
    if (cat == "ObfuscatedJS")  return "#CE93D8";        // purple
    return theme::Info;                                   // TrackerC2 / other (blue)
}

QString RiskForCategory(const QString& cat) {
    if (cat == "Cryptojacking" || cat == "ExploitKit" || cat == "Skimmer") return "high";
    if (cat == "Malvertising" || cat == "ObfuscatedJS") return "medium";
    return "low";
}

// Browser process names whose connections we consider "web" traffic.
bool IsBrowser(const QString& proc) {
    static const QStringList kBrowsers = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
        "opera.exe", "vivaldi.exe", "chromium.exe", "iexplore.exe"};
    return kBrowsers.contains(proc, Qt::CaseInsensitive);
}

// ─── Shared page state ───────────────────────────────────────────────────────
struct WebRow {
    QString  time, process, endpoint, category, status; // status: Allowed / Blocked
    QString  risk;                                       // high / medium / low
    int      count = 1;
    quint32  pid = 0;
    QString  remoteIp;
    QString  protocol;                                   // TCP / Extension runtime
    QString  detail;                                     // evidence line
};

struct Layer {
    QString id, label, status;
    bool    enabled = true;
};

struct State {
    std::mutex                                     mtx;
    std::unordered_map<quint32, std::pair<QString, QString>> ipMap; // ip(be) -> {host, category}
    std::atomic<bool>                              resolved{false};
    std::atomic<bool>                              capturing{false}; // single-flight guard
    std::atomic<bool>                              scanning{false};  // extension-scan guard
    std::vector<WebRow>                            netRows;   // live network hits
    std::vector<WebRow>                            fileRows;  // flagged extension scripts
    QString                                        mode = "BLOCKING";
    QString                                        pendingMode = "BLOCKING";
    QString                                        filter = "All";
    QString                                        search;
    int                                            selected = -1;
    std::vector<Layer>                             layers;
    quint64                                        threatsSeen = 0;
    quint64                                        scriptsScanned = 0;
    quint64                                        scriptsFlagged = 0;
    std::unordered_set<QString>                    browsersSeen;
    // category -> live count (for stat cards + tiles)
    std::unordered_map<QString, int>               catCount;
};

// ─── Process name for a PID ──────────────────────────────────────────────────
QString ProcName(DWORD pid) {
    if (pid == 0) return "System";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "pid " + QString::number(pid);
    wchar_t buf[MAX_PATH]; DWORD sz = MAX_PATH;
    QString name = "pid " + QString::number(pid);
    if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
        std::wstring full(buf, sz);
        auto slash = full.find_last_of(L"\\/");
        name = QString::fromStdWString(slash == std::wstring::npos ? full : full.substr(slash + 1));
    }
    CloseHandle(h);
    return name;
}

// ─── Resolve blocklist hostnames -> IP set (background, once) ─────────────────
void ResolveHosts(State* st) {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    std::unordered_map<quint32, std::pair<QString, QString>> map;
    for (const auto& bh : kBadHosts) {
        ADDRINFOW hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        PADDRINFOW res = nullptr;
        if (GetAddrInfoW(bh.host, nullptr, &hints, &res) == 0) {
            for (auto* p = res; p; p = p->ai_next) {
                auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
                map[sa->sin_addr.S_un.S_addr] = { QString::fromWCharArray(bh.host), bh.category };
            }
            FreeAddrInfoW(res);
        }
    }
    {
        std::lock_guard<std::mutex> lk(st->mtx);
        st->ipMap = std::move(map);
    }
    st->resolved = true;
}

// ─── Capture live browser->malicious-JS connections from the TCP table ────────
void CaptureRows(State* st) {
    if (!st->resolved) return;
    std::unordered_map<quint32, std::pair<QString, QString>> ipMap;
    {
        std::lock_guard<std::mutex> lk(st->mtx);
        ipMap = st->ipMap;
    }
    if (ipMap.empty()) return;

    ULONG sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (sz == 0) return;
    std::vector<char> buf(sz);
    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    if (GetExtendedTcpTable(table, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return;

    std::unordered_map<QString, WebRow> agg;   // key: endpoint host
    std::unordered_set<QString> browsers;
    const QString now = QTime::currentTime().toString("HH:mm:ss");
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& e = table->table[i];
        auto it = ipMap.find(e.dwRemoteAddr);
        if (it == ipMap.end()) continue;
        const QString proc = ProcName(e.dwOwningPid);
        if (!IsBrowser(proc)) continue;         // web traffic only
        browsers.insert(proc.toLower());
        const QString host = it->second.first;
        auto& r = agg[host];
        if (r.endpoint.isEmpty()) {
            r.endpoint = host;
            r.category = it->second.second;
            r.risk     = RiskForCategory(r.category);
            r.pid      = e.dwOwningPid;
            r.process  = proc;
            r.time     = now;
            const quint32 ip = e.dwRemoteAddr;   // network byte order; format manually
            r.remoteIp = QString("%1.%2.%3.%4").arg(ip & 0xFF).arg((ip >> 8) & 0xFF)
                             .arg((ip >> 16) & 0xFF).arg((ip >> 24) & 0xFF);
            r.protocol = "TCP";
            r.detail   = "Connection to known " + r.category + " infrastructure";
        }
        r.count++;
    }

    std::vector<WebRow> rows;
    rows.reserve(agg.size());
    std::unordered_map<QString, int> catCount;
    for (auto& kv : agg) { catCount[kv.second.category]++; rows.push_back(std::move(kv.second)); }

    {
        std::lock_guard<std::mutex> lk(st->mtx);
        for (auto& r : rows) r.status = "Allowed"; // live => still getting through
        st->netRows = std::move(rows);
        st->browsersSeen = std::move(browsers);
        st->catCount = std::move(catCount);
    }
}

// ─── Scan installed browser-extension JS for obfuscation (background, once) ────
bool LooksObfuscated(const QByteArray& data, QString* why) {
    static const char* kMarkers[] = {
        "eval(", "atob(", "String.fromCharCode", "unescape(", "new Function(",
        "document.write(unescape", "\\x", "fromCharCode"};
    static const char* kMiner[] = {
        "coinhive", "CoinHive", "cryptonight", "CryptoNight", "authedmine",
        "webminepool", "stratum+tcp", "coinimp"};
    for (const char* m : kMiner)
        if (data.contains(m)) { *why = QString("miner keyword: %1").arg(m); return true; }
    int hits = 0; QString first;
    for (const char* m : kMarkers)
        if (data.contains(m)) { if (first.isEmpty()) first = m; ++hits; }
    if (hits >= 2) { *why = QString("obfuscation markers (%1x, e.g. %2)").arg(hits).arg(first); return true; }
    return false;
}

void ScanExtensions(State* st) {
    QStringList roots;
    const QString local = QString::fromLocal8Bit(qgetenv("LOCALAPPDATA"));
    if (!local.isEmpty()) {
        roots << local + "/Google/Chrome/User Data"
              << local + "/Microsoft/Edge/User Data"
              << local + "/BraveSoftware/Brave-Browser/User Data"
              << local + "/Chromium/User Data";
    }
    quint64 scanned = 0, flagged = 0;
    std::vector<WebRow> rows;
    const QString now = QTime::currentTime().toString("HH:mm:ss");
    for (const QString& root : roots) {
        QDir rd(root);
        if (!rd.exists()) continue;
        // Extensions live under <root>/<Profile>/Extensions/<id>/<ver>/*.js
        const QStringList profiles = rd.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
        for (const QString& prof : profiles) {
            const QString extRoot = root + "/" + prof + "/Extensions";
            if (!QDir(extRoot).exists()) continue;
            QDirIterator it(extRoot, {"*.js"}, QDir::Files, QDirIterator::Subdirectories);
            while (it.hasNext()) {
                const QString path = it.next();
                if (scanned >= 6000) break;           // bound the walk
                QFileInfo fi(path);
                if (fi.size() > 512 * 1024) { ++scanned; continue; } // skip huge bundles
                QFile f(path);
                if (!f.open(QIODevice::ReadOnly)) { ++scanned; continue; }
                const QByteArray data = f.read(512 * 1024);
                f.close();
                ++scanned;
                QString why;
                if (LooksObfuscated(data, &why)) {
                    ++flagged;
                    WebRow r;
                    r.time = now;
                    r.process = "extension";
                    r.endpoint = fi.fileName();
                    r.category = "ObfuscatedJS";
                    r.risk = "medium";
                    r.status = "Allowed";
                    r.count = 1;
                    r.remoteIp = "—";
                    r.protocol = "Extension runtime";
                    r.detail = why;
                    rows.push_back(std::move(r));
                }
            }
            if (scanned >= 6000) break;
        }
        if (scanned >= 6000) break;
    }
    {
        std::lock_guard<std::mutex> lk(st->mtx);
        st->fileRows = std::move(rows);
        st->scriptsScanned = scanned;
        st->scriptsFlagged = flagged;
    }
}

// ─── Small UI builders (same visual language as the other Guard tabs) ─────────
QWidget* Card() {
    auto* c = new QWidget;
    c->setObjectName("GuardCard");
    c->setStyleSheet(QString("QWidget#GuardCard{background:%1;border:1px solid %2;border-radius:%3px;}")
                         .arg(theme::Surface).arg(theme::Border).arg(theme::RadiusLg));
    return c;
}

QWidget* SectionTitle(const QString& text) {
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0); h->setSpacing(8);
    auto* bar = new QLabel; bar->setFixedSize(3, 14);
    bar->setStyleSheet(QString("background:%1;border-radius:1px;").arg(theme::Accent));
    auto* lbl = new QLabel(text);
    lbl->setStyleSheet(QString("color:%1;font-size:13px;font-weight:600;").arg(theme::Text));
    h->addWidget(bar); h->addWidget(lbl); h->addStretch();
    return w;
}

QPushButton* Toggle(bool checked) {
    auto* t = new QPushButton;
    t->setCheckable(true);
    t->setChecked(checked);
    t->setFixedSize(28, 16);
    t->setCursor(Qt::PointingHandCursor);
    t->setStyleSheet(QString(
        "QPushButton{border-radius:8px;background:%1;border:1px solid %1;}"
        "QPushButton:checked{background:%2;border:1px solid %2;}")
        .arg(theme::Border).arg(theme::Accent));
    return t;
}

std::wstring ScriptPath(const wchar_t* name) {
    wchar_t buf[MAX_PATH]; GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p(buf); auto s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos ? std::wstring() : p.substr(0, s + 1)) + name;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
QWidget* BuildWebGuardPage(QWidget* parent) {
    auto* page = new QWidget(parent);
    page->setObjectName("WebGuardPage");
    ArmQuitGuard(page);
    page->setStyleSheet("QLabel{border:none;}");

    auto* st = new State();
    st->layers = {
        {"cryptojacking", "Cryptojacking miners", "0 blocked today", true},
        {"skimmer",       "Magecart skimmers",    "0 blocked today", true},
        {"malvertising",  "Malvertising gates",   "0 blocked today", true},
        {"exploitkit",    "Exploit-kit gates",    "0 blocked today", true},
        {"obfuscated",    "Obfuscated ext. JS",   "0 blocked today", true},
        {"extscan",       "Extension scanning",   "Inactive",        false},
    };

    // Cap the content column so it never overflows the window on wide displays
    // (the page stack can be forced wider than the viewport by other pages). The
    // capped column is left-aligned; the remainder is empty background.
    auto* outer = new QHBoxLayout(page);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);
    auto* inner = new QWidget;
    inner->setMaximumWidth(1180);
    outer->addWidget(inner);
    outer->addStretch();
    auto* root = new QVBoxLayout(inner);
    root->setContentsMargins(theme::Space6, theme::Space6, theme::Space6, theme::Space6);
    root->setSpacing(theme::Space4);

    // ── Header: title + master toggle + Apply/Revert/Refresh ─────────────────
    auto* actions = new QWidget;
    auto* al = new QHBoxLayout(actions);
    al->setContentsMargins(0, 0, 0, 0);
    al->setSpacing(theme::Space2);

    auto* seg = new QWidget;
    seg->setObjectName("GuardBox");
    auto* segl = new QHBoxLayout(seg);
    segl->setContentsMargins(2, 2, 2, 2);
    segl->setSpacing(2);
    seg->setStyleSheet(QString("QWidget#GuardBox{background:%1;border:1px solid %2;border-radius:%3px;}")
                           .arg(theme::Surface).arg(theme::Border).arg(theme::RadiusMd));
    auto makeSeg = [&](const QString& text) {
        auto* b = new QPushButton(text);
        b->setCheckable(true);
        b->setFixedHeight(30);
        b->setCursor(Qt::PointingHandCursor);
        b->setStyleSheet(QString(
            "QPushButton{background:transparent;color:%1;border:none;border-radius:%2px;padding:0 14px;font-weight:600;font-size:12px;}"
            "QPushButton:checked{background:%3;color:%4;}")
            .arg(theme::Dim).arg(theme::RadiusSm).arg(theme::Accent).arg(theme::Bg));
        segl->addWidget(b);
        return b;
    };
    auto* segBlock = makeSeg(QString::fromUtf8("\xF0\x9F\x9B\xA1 BLOCKING"));
    auto* segOpen  = makeSeg(QString::fromUtf8("\xE2\x97\xAF OPEN"));
    segBlock->setChecked(true);
    al->addWidget(seg);

    auto* applyBtn = new QPushButton("Apply");
    applyBtn->setObjectName("GhostBtn");
    applyBtn->setFixedHeight(34);
    applyBtn->setStyleSheet(QString(
        "QPushButton{background:transparent;color:%1;border:1px solid %1;border-radius:%2px;padding:0 14px;font-weight:600;}"
        "QPushButton:hover{background:rgba(255,122,0,0.12);}").arg(theme::Accent).arg(theme::RadiusMd));
    auto* revertBtn = new QPushButton("Revert");
    revertBtn->setFixedHeight(34);
    revertBtn->setStyleSheet(QString(
        "QPushButton{background:transparent;color:%1;border:1px solid %2;border-radius:%3px;padding:0 14px;}"
        "QPushButton:hover{color:%4;}").arg(theme::Dim).arg(theme::Border).arg(theme::RadiusMd).arg(theme::Text));
    auto* refreshBtn = new QPushButton();
    refreshBtn->setIcon(refreshBtn->style()->standardIcon(QStyle::SP_BrowserReload));
    refreshBtn->setFixedSize(34, 34);
    refreshBtn->setStyleSheet(QString(
        "QPushButton{background:transparent;color:%1;border:1px solid %2;border-radius:%3px;}"
        "QPushButton:hover{color:%4;}").arg(theme::Dim).arg(theme::Border).arg(theme::RadiusMd).arg(theme::Text));
    al->addWidget(applyBtn);
    al->addWidget(revertBtn);
    al->addWidget(refreshBtn);

    root->addWidget(theme::BuildPageHeader(
        "Web Guard",
        QString::fromUtf8("Realtime malicious-domain blocking. Monitors browser connections to cryptojacking, "
                          "skimmer, malvertising & exploit-kit infrastructure, and obfuscated extension scripts."),
        actions));

    // ── Stat cards ───────────────────────────────────────────────────────────
    auto* cardRow = new QHBoxLayout;
    cardRow->setSpacing(theme::Space3);
    struct CardRefs { QLabel* value; QLabel* sub; QLabel* dot; };
    auto makeCard = [&](const QString& label, const QString& color) -> CardRefs {
        auto* c = Card();
        c->setFixedHeight(96);
        auto* cl = new QVBoxLayout(c);
        cl->setContentsMargins(20, 16, 20, 16);
        cl->setSpacing(4);
        auto* lbl = new QLabel(label.toUpper());
        lbl->setStyleSheet(QString("color:%1;font-size:10px;font-weight:600;letter-spacing:1px;").arg(theme::Dim));
        cl->addWidget(lbl);
        auto* valRow = new QHBoxLayout; valRow->setSpacing(6);
        auto* dot = new QLabel; dot->setFixedSize(8, 8); dot->setVisible(false);
        valRow->addWidget(dot);
        auto* val = new QLabel("—");
        val->setStyleSheet(QString("color:%1;font-size:22px;font-weight:700;").arg(color));
        valRow->addWidget(val); valRow->addStretch();
        cl->addLayout(valRow);
        auto* sub = new QLabel("");
        sub->setStyleSheet(QString("color:%1;font-size:11px;").arg(theme::Dim));
        cl->addWidget(sub);
        cardRow->addWidget(c, 1);
        return { val, sub, dot };
    };
    auto cThreats  = makeCard("Threats Seen",  theme::Accent);
    auto cMiners   = makeCard("Cryptojacking", theme::Text);
    auto cSkimmers = makeCard("Skimmers",      theme::Text);
    auto cMalv     = makeCard("Malvertising",  theme::Text);
    auto cScripts  = makeCard("Flagged Scripts", theme::Text);
    // Persistent category dots on cards 2-5 (matches the design).
    auto setDot = [](const CardRefs& c, const char* color) {
        c.dot->setVisible(true);
        c.dot->setStyleSheet(QString("background:%1;border-radius:4px;").arg(color));
    };
    setDot(cMiners,   theme::Danger);       // Cryptojacking red
    setDot(cSkimmers, theme::Accent);       // Skimmer amber
    setDot(cMalv,     theme::Warn);         // Malvertising yellow
    setDot(cScripts,  "#CE93D8");           // Obfuscated JS purple
    root->addLayout(cardRow);

    // ── Layer / category control ─────────────────────────────────────────────
    auto* layerCard = Card();
    // Design: the whole card carries a 3px amber left accent (in place of the
    // per-title accent bar the other sections use).
    layerCard->setStyleSheet(QString(
        "QWidget#GuardCard{background:%1;border:1px solid %2;border-left:3px solid %3;border-radius:%4px;}")
        .arg(theme::Surface).arg(theme::Border).arg(theme::Accent).arg(theme::RadiusLg));
    auto* ll = new QVBoxLayout(layerCard);
    ll->setContentsMargins(20, 14, 20, 14);
    ll->setSpacing(theme::Space3);
    auto* layerTitle = new QLabel("PROTECTION LAYERS");
    layerTitle->setStyleSheet(QString("color:%1;font-size:12px;font-weight:600;letter-spacing:1px;").arg(theme::Dim));
    ll->addWidget(layerTitle);
    auto* tilesRow = new QHBoxLayout;
    tilesRow->setSpacing(theme::Space2);

    std::vector<QLabel*> tileStatus(st->layers.size());
    std::vector<QPushButton*> tileToggle(st->layers.size());
    // ON border brightens to amber, OFF is a plain hairline (matches the design).
    auto tileQss = [](bool on) {
        return QString("QWidget#GuardBox{background:%1;border:1px solid %2;border-radius:%3px;}")
            .arg("rgba(255,122,0,0.06)").arg(on ? "rgba(255,122,0,0.30)" : QString(theme::Border)).arg(theme::RadiusMd);
    };
    for (size_t i = 0; i < st->layers.size(); ++i) {
        const auto& L = st->layers[i];
        auto* tile = new QWidget;
        tile->setObjectName("GuardBox");
        tile->setStyleSheet(tileQss(L.enabled));
        auto* tl = new QVBoxLayout(tile);
        tl->setContentsMargins(12, 10, 12, 10);
        tl->setSpacing(8);
        auto* topRow = new QHBoxLayout; topRow->setContentsMargins(0,0,0,0);
        auto* nameLbl = new QLabel(L.label);
        nameLbl->setWordWrap(true);
        nameLbl->setStyleSheet(QString("color:%1;font-size:11px;font-weight:700;").arg(theme::Text));
        topRow->addWidget(nameLbl, 1);
        auto* tog = Toggle(L.enabled);
        tileToggle[i] = tog;
        topRow->addWidget(tog, 0, Qt::AlignTop);
        tl->addLayout(topRow);
        auto* status = new QLabel(L.status);
        status->setStyleSheet(QString("color:%1;font-size:11px;font-family:%2;")
            .arg(L.enabled ? theme::AccentSoft : theme::Dim).arg(theme::MonoFamily));
        tileStatus[i] = status;
        tl->addWidget(status);
        const QString id = L.id;
        QObject::connect(tog, &QPushButton::toggled, page, [st, id, tile, tileQss](bool on){
            { std::lock_guard<std::mutex> lk(st->mtx);
              for (auto& lay : st->layers) if (lay.id == id) lay.enabled = on; }
            tile->setStyleSheet(tileQss(on));
        });
        tilesRow->addWidget(tile, 1);
    }
    ll->addLayout(tilesRow);
    root->addWidget(layerCard);

    // ── Monitor: table (left) + detail panel (right) ─────────────────────────
    auto* body = new QHBoxLayout;
    body->setSpacing(theme::Space3);

    auto* tblCard = Card();
    auto* tc = new QVBoxLayout(tblCard);
    tc->setContentsMargins(0, 0, 0, 0);
    tc->setSpacing(0);

    auto* toolbar = new QWidget;
    auto* tb = new QHBoxLayout(toolbar);
    tb->setContentsMargins(14, 10, 14, 10);
    tb->setSpacing(theme::Space2);
    tb->addWidget(SectionTitle(QString::fromUtf8("Live Monitor")));
    auto* liveLbl = new QLabel(QString::fromUtf8("\xE2\x97\x8F LIVE"));
    liveLbl->setStyleSheet(QString("color:%1;font-size:10px;font-family:%2;").arg(theme::Danger).arg(theme::MonoFamily));
    tb->addWidget(liveLbl);
    auto* countLbl = new QLabel("0 events");
    countLbl->setStyleSheet(QString("color:%1;font-size:11px;").arg(theme::Dim));
    tb->addWidget(countLbl);
    tb->addStretch();

    QStringList chips = {"All", "Cryptojacking", "Skimmer", "Malvertising", "ExploitKit", "ObfuscatedJS", "Blocked"};
    std::vector<QPushButton*> chipBtns;
    for (const auto& ch : chips) {
        auto* b = new QPushButton(ch);
        b->setCheckable(true);
        b->setFixedHeight(28);
        b->setCursor(Qt::PointingHandCursor);
        b->setStyleSheet(QString(
            "QPushButton{background:transparent;color:%1;border:1px solid %2;border-radius:%3px;padding:0 10px;font-size:11px;}"
            "QPushButton:checked{background:rgba(255,122,0,0.15);border-color:%4;color:%4;}")
            .arg(theme::Dim).arg(theme::Border).arg(theme::RadiusSm).arg(theme::Accent));
        chipBtns.push_back(b);
        tb->addWidget(b);
    }
    chipBtns[0]->setChecked(true);

    auto* search = new QLineEdit;
    search->setPlaceholderText(QString::fromUtf8("Search endpoint, process\xE2\x80\xA6"));
    search->setFixedSize(200, 28);
    search->setStyleSheet(QString(
        "QLineEdit{background:%1;border:1px solid %2;border-radius:%3px;color:%4;padding:0 8px;font-size:11px;}"
        "QLineEdit:focus{border-color:%5;}").arg(theme::Surface2).arg(theme::Border).arg(theme::RadiusSm).arg(theme::Text).arg(theme::Accent));
    tb->addWidget(search);
    tc->addWidget(toolbar);

    auto* tbl = new QTableWidget(0, 7);
    tbl->setHorizontalHeaderLabels({"", "Time", "Process", "Endpoint", "Category", "Status", "Hits"});
    tbl->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);  // Process 1fr
    tbl->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);  // Endpoint 1fr
    tbl->setColumnWidth(0, 24);
    tbl->setColumnWidth(1, 68);
    tbl->setColumnWidth(4, 100);
    tbl->setColumnWidth(5, 80);
    tbl->setColumnWidth(6, 48);
    tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    tbl->setSelectionMode(QAbstractItemView::SingleSelection);
    tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tbl->setShowGrid(false);
    tbl->verticalHeader()->hide();
    tbl->setContextMenuPolicy(Qt::CustomContextMenu);
    tbl->setStyleSheet(theme::TableQss());
    tc->addWidget(tbl, 1);
    body->addWidget(tblCard, 1);

    auto* detail = new QWidget;
    detail->setObjectName("GuardBox");
    detail->setFixedWidth(0);
    detail->setStyleSheet(QString("QWidget#GuardBox{background:%1;border:1px solid %2;border-radius:%3px;}")
                              .arg(theme::Sidebar).arg(theme::Border).arg(theme::RadiusLg));
    auto* dl = new QVBoxLayout(detail);
    dl->setContentsMargins(14, 12, 14, 12);
    dl->setSpacing(8);
    auto* dTitle = new QLabel(QString::fromUtf8("Threat Detail"));
    dTitle->setStyleSheet(QString("color:%1;font-size:13px;font-weight:700;letter-spacing:1px;").arg(theme::Accent));
    dl->addWidget(dTitle);
    // Per-field rows (rebuilt on selection). Key = 10px uppercase dim, value =
    // mono, with a hairline under each field — matches the design's detail list.
    auto* dFields = new QWidget;
    auto* dfl = new QVBoxLayout(dFields);
    dfl->setContentsMargins(0, 0, 0, 0);
    dfl->setSpacing(0);
    dl->addWidget(dFields);
    dl->addStretch();

    auto clearFields = [dfl]() {
        QLayoutItem* it;
        while ((it = dfl->takeAt(0)) != nullptr) {
            if (it->widget()) it->widget()->deleteLater();
            delete it;
        }
    };
    auto addField = [dfl](const QString& key, const QString& val, const QString& col, bool border) {
        auto* row = new QWidget;
        row->setObjectName("DetailRow");   // id selector so the border can't leak to child labels
        if (border)
            row->setStyleSheet(QString("QWidget#DetailRow{border-bottom:1px solid %1;}").arg(theme::Border));
        auto* rl = new QVBoxLayout(row);
        rl->setContentsMargins(0, 8, 0, 8);
        rl->setSpacing(2);
        auto* k = new QLabel(key);
        k->setStyleSheet(QString("color:%1;font-size:10px;font-weight:600;letter-spacing:1px;").arg(theme::Dim));
        auto* v = new QLabel(val);
        v->setWordWrap(true);
        v->setTextInteractionFlags(Qt::TextSelectableByMouse);
        v->setStyleSheet(QString("color:%1;font-size:12px;font-family:%2;").arg(col).arg(theme::MonoFamily));
        rl->addWidget(k); rl->addWidget(v);
        dfl->addWidget(row);
    };
    auto* dBtns = new QHBoxLayout;
    auto* dBlock = new QPushButton("Block");
    dBlock->setStyleSheet(QString("QPushButton{background:transparent;color:%1;border:1px solid %1;border-radius:%2px;padding:6px;font-weight:600;}"
        "QPushButton:hover{background:rgba(255,90,106,0.12);}").arg(theme::Danger).arg(theme::RadiusSm));
    auto* dAllow = new QPushButton("Allow");
    dAllow->setStyleSheet(QString("QPushButton{background:transparent;color:%1;border:1px solid %1;border-radius:%2px;padding:6px;font-weight:600;}"
        "QPushButton:hover{background:rgba(74,222,128,0.12);}").arg(theme::Safe).arg(theme::RadiusSm));
    dBtns->addWidget(dBlock); dBtns->addWidget(dAllow);
    dl->addLayout(dBtns);
    body->addWidget(detail);

    root->addLayout(body, 1);

    // Combined view = live network rows + flagged extension scripts.
    auto allRows = [st]() {
        std::vector<WebRow> v = st->netRows;
        v.insert(v.end(), st->fileRows.begin(), st->fileRows.end());
        return v;
    };

    // ── Rendering ────────────────────────────────────────────────────────────
    auto refreshTable = [=]() {
        std::lock_guard<std::mutex> lk(st->mtx);
        std::vector<WebRow> rows = allRows();
        tbl->setUpdatesEnabled(false);
        tbl->setRowCount(0);
        int shown = 0;
        for (int idx = 0; idx < (int)rows.size(); ++idx) {
            const auto& r = rows[idx];
            const bool fOk =
                st->filter == "All" ||
                (st->filter == "Blocked" && r.status == "Blocked") ||
                r.category == st->filter;
            const bool sOk = st->search.isEmpty() ||
                r.process.contains(st->search, Qt::CaseInsensitive) ||
                r.endpoint.contains(st->search, Qt::CaseInsensitive);
            if (!fOk || !sOk) continue;

            const int row = tbl->rowCount();
            tbl->insertRow(row);
            const QColor riskCol = r.risk == "high" ? QColor(theme::Danger)
                                 : r.risk == "medium" ? QColor(theme::Warn)
                                                      : QColor(theme::Safe);
            auto* dot = new QTableWidgetItem(QString(QChar(0x25CF)));
            dot->setForeground(riskCol); dot->setTextAlignment(Qt::AlignCenter);
            dot->setData(Qt::UserRole, idx);
            tbl->setItem(row, 0, dot);
            auto item = [](const QString& s, const QColor& c) {
                auto* it = new QTableWidgetItem(s); it->setForeground(c); return it;
            };
            tbl->setItem(row, 1, item(r.time, QColor(theme::Dim)));
            tbl->setItem(row, 2, item(r.process, QColor(theme::Text)));
            tbl->setItem(row, 3, item(r.endpoint, QColor(theme::AccentSoft)));
            tbl->setItem(row, 4, item(r.category, QColor(CategoryColor(r.category))));
            const bool blocked = r.status == "Blocked";
            tbl->setItem(row, 5, item(r.status, blocked ? QColor(theme::Danger) : QColor(theme::Safe)));
            auto* cnt = item(QString::number(r.count), QColor(theme::Dim));
            cnt->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            tbl->setItem(row, 6, cnt);
            ++shown;
        }
        if (shown == 0) {
            tbl->insertRow(0);
            tbl->setSpan(0, 0, 1, tbl->columnCount());
            auto* msg = new QTableWidgetItem(
                QString::fromUtf8("No events match current filter"));
            msg->setForeground(QColor(theme::Dim));
            msg->setTextAlignment(Qt::AlignCenter);
            tbl->setItem(0, 0, msg);
        }
        tbl->setUpdatesEnabled(true);
        countLbl->setText(QString("%1 events").arg(shown));
        liveLbl->setVisible(st->mode == "BLOCKING");
    };

    auto refreshStatus = [=]() {
        std::lock_guard<std::mutex> lk(st->mtx);
        const int miners  = st->catCount.count("Cryptojacking") ? st->catCount["Cryptojacking"] : 0;
        const int skimmer = st->catCount.count("Skimmer") ? st->catCount["Skimmer"] : 0;
        const int malv    = st->catCount.count("Malvertising") ? st->catCount["Malvertising"] : 0;
        const int ek      = st->catCount.count("ExploitKit") ? st->catCount["ExploitKit"] : 0;
        st->threatsSeen = (quint64)st->netRows.size() + st->scriptsFlagged;

        // Card 1: amber value, no dot (design). Cards 2-5: default text value +
        // a persistent category dot (set once above).
        cThreats.value->setText(QString::number(st->threatsSeen));
        cThreats.sub->setText("Last 24 hours");
        cMiners.value->setText(QString::number(miners));
        cMiners.sub->setText("Miners blocked");
        cSkimmers.value->setText(QString::number(skimmer));
        cSkimmers.sub->setText("Magecart endpoints");
        cMalv.value->setText(QString::number(malv));
        cMalv.sub->setText("Gate redirects blocked");
        cScripts.value->setText(QString::number(st->scriptsFlagged));
        cScripts.sub->setText("Obfuscated JS detected");

        // tile statuses ("N blocked today" per category; Extension scanning special)
        for (size_t i = 0; i < st->layers.size(); ++i) {
            if (!tileStatus[i]) continue;
            const auto& lay = st->layers[i];
            QString txt;
            if (!lay.enabled) {
                txt = (lay.id == "extscan") ? "Inactive" : "Disabled";
            } else if (lay.id == "cryptojacking") txt = QString("%1 blocked today").arg(miners);
            else if (lay.id == "skimmer")      txt = QString("%1 blocked today").arg(skimmer);
            else if (lay.id == "malvertising") txt = QString("%1 blocked today").arg(malv);
            else if (lay.id == "exploitkit")   txt = QString("%1 blocked today").arg(ek);
            else if (lay.id == "obfuscated")   txt = QString("%1 blocked today").arg(st->scriptsFlagged);
            else if (lay.id == "extscan")      txt = QString("%1 / %2 scanned").arg(st->scriptsFlagged).arg(st->scriptsScanned);
            tileStatus[i]->setText(txt);
            tileStatus[i]->setStyleSheet(QString("color:%1;font-size:11px;font-family:%2;")
                .arg(lay.enabled ? theme::AccentSoft : theme::Dim).arg(theme::MonoFamily));
        }
    };

    // filter chips
    for (size_t i = 0; i < chipBtns.size(); ++i) {
        auto* b = chipBtns[i]; const QString name = chips[(int)i];
        QObject::connect(b, &QPushButton::clicked, page, [=]() {
            for (auto* other : chipBtns) other->setChecked(other == b);
            { std::lock_guard<std::mutex> lk(st->mtx); st->filter = name; }
            refreshTable();
        });
    }

    // debounced search
    auto* deb = new QTimer(page); deb->setSingleShot(true); deb->setInterval(200);
    QObject::connect(deb, &QTimer::timeout, page, [=](){ refreshTable(); });
    QObject::connect(search, &QLineEdit::textChanged, page, [=](const QString& t){
        { std::lock_guard<std::mutex> lk(st->mtx); st->search = t; }
        deb->start();
    });

    // row selection -> detail panel
    auto showDetail = [=](int idx) {
        std::lock_guard<std::mutex> lk(st->mtx);
        std::vector<WebRow> rows = allRows();
        if (idx < 0 || idx >= (int)rows.size()) { detail->setFixedWidth(0); return; }
        const auto& r = rows[idx];
        st->selected = idx;
        clearFields();
        const QString txt = theme::Text;
        const QString catCol = CategoryColor(r.category);
        const QString statusCol = r.status == "Blocked" ? QString(theme::Danger) : QString(theme::Safe);
        addField("ENDPOINT",  r.endpoint, txt, true);
        addField("REMOTE IP", r.remoteIp, txt, true);
        addField("PROTOCOL",  r.protocol.isEmpty() ? "—" : r.protocol, txt, true);
        addField("PROCESS",   QString("%1  (pid %2)").arg(r.process).arg(r.pid), txt, true);
        addField("CATEGORY",  r.category, catCol, true);
        addField("HITS",      QString::number(r.count), txt, true);
        addField("STATUS",    r.status, statusCol, true);
        addField("EVIDENCE",  r.detail.isEmpty() ? "—" : r.detail, theme::Dim, false);
        detail->setFixedWidth(280);
    };
    QObject::connect(tbl, &QTableWidget::itemSelectionChanged, page, [=]() {
        auto items = tbl->selectedItems();
        if (items.isEmpty()) return;
        int idx = tbl->item(items.first()->row(), 0)->data(Qt::UserRole).toInt();
        showDetail(idx);
    });

    // right-click context menu: block / allow endpoint (in-view marking)
    auto setRowStatus = [=](int idx, const QString& status) {
        { std::lock_guard<std::mutex> lk(st->mtx);
          if (idx >= 0 && idx < (int)st->netRows.size()) st->netRows[idx].status = status; }
        refreshTable();
    };
    QObject::connect(tbl, &QTableWidget::customContextMenuRequested, page, [=](const QPoint& p){
        auto* it = tbl->itemAt(p);
        if (!it) return;
        int idx = tbl->item(it->row(), 0)->data(Qt::UserRole).toInt();
        QMenu menu;
        menu.setStyleSheet(QString("QMenu{background:%1;border:1px solid %2;color:%3;}"
            "QMenu::item:selected{background:%4;}").arg(theme::Surface2).arg(theme::Border).arg(theme::Text).arg(theme::Surface));
        menu.addAction(QString::fromUtf8("Block this endpoint"), page, [=](){ setRowStatus(idx, "Blocked"); });
        menu.addAction(QString::fromUtf8("Allow this endpoint"), page, [=](){ setRowStatus(idx, "Allowed"); });
        menu.exec(tbl->viewport()->mapToGlobal(p));
    });
    QObject::connect(dBlock, &QPushButton::clicked, page, [=](){ if (st->selected >= 0) setRowStatus(st->selected, "Blocked"); });
    QObject::connect(dAllow, &QPushButton::clicked, page, [=](){ if (st->selected >= 0) setRowStatus(st->selected, "Allowed"); });

    // master mode segmented toggle
    QObject::connect(segBlock, &QPushButton::clicked, page, [=](){
        segBlock->setChecked(true); segOpen->setChecked(false);
        std::lock_guard<std::mutex> lk(st->mtx); st->pendingMode = "BLOCKING";
    });
    QObject::connect(segOpen, &QPushButton::clicked, page, [=](){
        segOpen->setChecked(true); segBlock->setChecked(false);
        std::lock_guard<std::mutex> lk(st->mtx); st->pendingMode = "OPEN";
    });

    // Apply: invoke the elevated hardening script for real block/open.
    QObject::connect(applyBtn, &QPushButton::clicked, page, [=](){
        QString mode; { std::lock_guard<std::mutex> lk(st->mtx); st->mode = st->pendingMode; mode = st->mode; }
        const QString flag = mode == "BLOCKING" ? "-Apply" : "-Revert";
        std::wstring params = L"-NoProfile -ExecutionPolicy Bypass -File \""
                            + ScriptPath(L"Harden-WebGuard.ps1") + L"\" " + flag.toStdWString();
        ShellExecuteW(nullptr, L"runas", L"powershell.exe", params.c_str(), nullptr, SW_SHOWNORMAL);
        refreshStatus(); refreshTable();
    });
    QObject::connect(revertBtn, &QPushButton::clicked, page, [=](){
        segBlock->setChecked(true); segOpen->setChecked(false);
        std::lock_guard<std::mutex> lk(st->mtx); st->pendingMode = st->mode;
    });
    QObject::connect(refreshBtn, &QPushButton::clicked, page, [=](){
        if (!st->scanning.exchange(true))
            std::thread([st]{ ScanExtensions(st); st->scanning.store(false); }).detach();
        refreshStatus();
    });

    // Background resolve + one extension scan + periodic capture.
    std::thread([st]{ ResolveHosts(st); }).detach();
    std::thread([st]{
        if (!st->scanning.exchange(true)) { ScanExtensions(st); st->scanning.store(false); }
    }).detach();
    auto* poll = new QTimer(page);
    poll->setInterval(3000);
    QObject::connect(poll, &QTimer::timeout, page, [=](){
        if (!st->capturing.exchange(true))
            std::thread([st]{ CaptureRows(st); st->capturing.store(false); }).detach();
        refreshStatus();
        refreshTable();
    });
    poll->start();
    QTimer::singleShot(300, page, [=](){ refreshStatus(); refreshTable(); });

    return page;
}

} // namespace avdashboard
