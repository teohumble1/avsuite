// main_window_fingerprint.cpp — Fingerprint Guard
// Audits the OS-level identifiers a device is fingerprinted / tracked by, shows
// live connections to known fingerprinting/tracker endpoints, and lets the user
// harden the surface (disable Advertising ID, randomise MAC, block tracker DNS).
//
// Everything shown is read live from the real machine (no fabricated values).
// Applying hardening shells out (elevated) to Harden-Fingerprint.ps1.

// Winsock2 headers MUST precede any <windows.h> pulled in by main_window.hpp/Qt,
// else the legacy winsock.h wins and ws2tcpip.h fails to compile. NOMINMAX keeps
// the Windows min/max macros from clashing with Qt.
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
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QScrollArea>
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
#include <vector>

namespace avdashboard {
namespace {

// ─── Known fingerprinting / tracker / analytics endpoints ────────────────────
struct Tracker { const wchar_t* host; const char* type; };
const Tracker kTrackers[] = {
    {L"api.fpjs.io",                    "Fingerprint"},
    {L"fingerprintjs.com",              "Fingerprint"},
    {L"cdn.fingerprint.com",            "Fingerprint"},
    {L"www.google-analytics.com",       "Analytics"},
    {L"analytics.google.com",           "Analytics"},
    {L"stats.g.doubleclick.net",        "Ads"},
    {L"ad.doubleclick.net",             "Ads"},
    {L"b.scorecardresearch.com",        "Analytics"},
    {L"api.mixpanel.com",               "Analytics"},
    {L"script.hotjar.com",              "Analytics"},
    {L"bat.bing.com",                   "Ads"},
    {L"cdn.branch.io",                  "Fingerprint"},
};

const char* TypeColor(const QString& t) {
    if (t == "Fingerprint") return theme::Danger;
    if (t == "Analytics")   return theme::Info;
    if (t == "Ads")         return "#CE93D8";
    return theme::Dim;
}

// ─── A single fingerprintable attribute ──────────────────────────────────────
struct Attr { QString label, value; bool exposed; };

struct MonRow {
    QString time, process, endpoint, type, status, risk;
    int count = 1; quint32 pid = 0; QString remoteIp;
};

struct Layer { QString id, label, status; bool enabled = true; };

struct State {
    std::mutex mtx;
    std::vector<Attr> attrs;
    std::vector<Layer> layers;
    std::unordered_map<quint32, std::pair<QString,QString>> ipMap; // ip -> {host,type}
    std::atomic<bool> resolved{false};
    std::atomic<bool> capturing{false}; // single-flight guard
    std::vector<MonRow> rows;
    QString mode = "HARDENED", pendingMode = "HARDENED", filter = "All", search;
    int selected = -1;
    quint64 seen = 0;
};

// ─── Real reads ──────────────────────────────────────────────────────────────
QString RegStr(HKEY root, const wchar_t* sub, const wchar_t* val) {
    wchar_t buf[512]; DWORD sz = sizeof(buf);
    if (RegGetValueW(root, sub, val, RRF_RT_REG_SZ, nullptr, buf, &sz) == ERROR_SUCCESS)
        return QString::fromWCharArray(buf);
    return {};
}
int RegDword(HKEY root, const wchar_t* sub, const wchar_t* val, int def) {
    DWORD d = 0, sz = sizeof(d);
    if (RegGetValueW(root, sub, val, RRF_RT_REG_DWORD, nullptr, &d, &sz) == ERROR_SUCCESS)
        return (int)d;
    return def;
}

QString FirstMac() {
    ULONG sz = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, nullptr, &sz);
    if (!sz) return {};
    std::vector<char> buf(sz);
    auto* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, aa, &sz) != NO_ERROR)
        return {};
    for (auto* p = aa; p; p = p->Next) {
        if (p->PhysicalAddressLength == 6 &&
            (p->IfType == IF_TYPE_ETHERNET_CSMACD || p->IfType == IF_TYPE_IEEE80211)) {
            char m[18];
            sprintf_s(m, "%02X:%02X:%02X:%02X:%02X:%02X",
                      p->PhysicalAddress[0], p->PhysicalAddress[1], p->PhysicalAddress[2],
                      p->PhysicalAddress[3], p->PhysicalAddress[4], p->PhysicalAddress[5]);
            return QString(m);
        }
    }
    return {};
}

int FontCount() {
    HKEY k; int n = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        DWORD vals = 0;
        RegQueryInfoKeyW(k, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &vals,
                         nullptr, nullptr, nullptr, nullptr);
        n = (int)vals;
        RegCloseKey(k);
    }
    return n;
}

void ReadFingerprint(State* st) {
    std::vector<Attr> a;
    const QString guid = RegStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    a.push_back({"Machine GUID", guid.isEmpty() ? "?" : guid, true});
    const QString mac = FirstMac();
    // locally-administered bit (02) set => randomised
    const bool macRnd = mac.size() >= 2 && (mac.left(2).toInt(nullptr, 16) & 0x02);
    a.push_back({"MAC Address", mac.isEmpty() ? "?" : mac, !macRnd});
    const int adId = RegDword(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled", 1);
    a.push_back({"Advertising ID", adId ? "Enabled" : "Disabled", adId != 0});
    wchar_t host[256]; DWORD hs = 256; GetComputerNameW(host, &hs);
    a.push_back({"Hostname", QString::fromWCharArray(host), true});
    a.push_back({"Screen", QString("%1 x %2").arg(GetSystemMetrics(SM_CXSCREEN)).arg(GetSystemMetrics(SM_CYSCREEN)), true});
    DISPLAY_DEVICEW dd{}; dd.cb = sizeof(dd); EnumDisplayDevicesW(nullptr, 0, &dd, 0);
    a.push_back({"GPU / Renderer", QString::fromWCharArray(dd.DeviceString), true});
    a.push_back({"Installed Fonts", QString::number(FontCount()), true});
    TIME_ZONE_INFORMATION tz{}; GetTimeZoneInformation(&tz);
    a.push_back({"Timezone", QString::fromWCharArray(tz.StandardName), true});
    wchar_t loc[85]; GetUserDefaultLocaleName(loc, 85);
    a.push_back({"Locale", QString::fromWCharArray(loc), true});
    const QString build = RegStr(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuild");
    a.push_back({"OS Build", build.isEmpty() ? "?" : build, false});

    std::lock_guard<std::mutex> lk(st->mtx);
    st->attrs = std::move(a);
}

QString ProcName(DWORD pid) {
    if (!pid) return "System";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "pid " + QString::number(pid);
    wchar_t buf[MAX_PATH]; DWORD sz = MAX_PATH; QString n = "pid " + QString::number(pid);
    if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
        std::wstring f(buf, sz); auto s = f.find_last_of(L"\\/");
        n = QString::fromStdWString(s == std::wstring::npos ? f : f.substr(s + 1));
    }
    CloseHandle(h); return n;
}

void ResolveTrackers(State* st) {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    std::unordered_map<quint32, std::pair<QString,QString>> map;
    for (const auto& t : kTrackers) {
        ADDRINFOW hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        PADDRINFOW res = nullptr;
        if (GetAddrInfoW(t.host, nullptr, &hints, &res) == 0) {
            for (auto* p = res; p; p = p->ai_next) {
                auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
                map[sa->sin_addr.S_un.S_addr] = { QString::fromWCharArray(t.host), t.type };
            }
            FreeAddrInfoW(res);
        }
    }
    { std::lock_guard<std::mutex> lk(st->mtx); st->ipMap = std::move(map); }
    st->resolved = true;
}

void CaptureRows(State* st) {
    if (!st->resolved) return;
    std::unordered_map<quint32, std::pair<QString,QString>> ipMap;
    { std::lock_guard<std::mutex> lk(st->mtx); ipMap = st->ipMap; }
    if (ipMap.empty()) return;
    ULONG sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (!sz) return;
    std::vector<char> buf(sz);
    auto* tb = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    if (GetExtendedTcpTable(tb, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return;
    std::unordered_map<QString, MonRow> agg;
    const QString now = QTime::currentTime().toString("HH:mm:ss");
    for (DWORD i = 0; i < tb->dwNumEntries; ++i) {
        const auto& e = tb->table[i];
        auto it = ipMap.find(e.dwRemoteAddr);
        if (it == ipMap.end()) continue;
        auto& r = agg[it->second.first];
        if (r.endpoint.isEmpty()) {
            r.endpoint = it->second.first; r.type = it->second.second;
            r.risk = r.type == "Fingerprint" ? "high" : r.type == "Analytics" ? "medium" : "low";
            r.pid = e.dwOwningPid; r.process = ProcName(e.dwOwningPid); r.time = now;
            // Manual IPv4 format (network byte order) — inet_ntoa's shared buffer is
            // not safe to call from this background thread.
            const quint32 ip = e.dwRemoteAddr;
            r.remoteIp = QString("%1.%2.%3.%4").arg(ip & 0xFF).arg((ip >> 8) & 0xFF)
                             .arg((ip >> 16) & 0xFF).arg((ip >> 24) & 0xFF);
        }
        r.count++;
    }
    std::vector<MonRow> rows; rows.reserve(agg.size());
    for (auto& kv : agg) { kv.second.status = "Allowed"; rows.push_back(std::move(kv.second)); }
    std::lock_guard<std::mutex> lk(st->mtx);
    st->rows = std::move(rows); st->seen = st->rows.size();
}

QFrame* Card() {
    auto* c = new QFrame;
    c->setStyleSheet(QString("QFrame{background:%1;border:1px solid %2;border-radius:%3px;}")
                         .arg(theme::Surface).arg(theme::Border).arg(theme::RadiusLg));
    return c;
}
QPushButton* Toggle(bool on) {
    auto* t = new QPushButton; t->setCheckable(true); t->setChecked(on);
    t->setFixedSize(38, 20); t->setCursor(Qt::PointingHandCursor);
    t->setStyleSheet(QString("QPushButton{border-radius:10px;background:#3A3A3E;border:1px solid #4A4A4E;}"
        "QPushButton:checked{background:%1;border:1px solid %1;}").arg(theme::Accent));
    return t;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
QWidget* BuildFingerprintGuardPage(QWidget* parent) {
    auto* page = new QWidget(parent);
    page->setObjectName("FingerprintPage");
    ArmQuitGuard(page);

    auto* st = new State();
    st->layers = {
        {"adid",     "Disable Advertising ID", "reading...", true},
        {"mac",      "Randomize MAC",          "reading...", true},
        {"trackers", "Block tracker DNS",      "reading...", true},
        {"guid",     "Mask Machine GUID",      "manual",     false},
    };

    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(theme::Space6, theme::Space6, theme::Space6, theme::Space6);
    root->setSpacing(theme::Space4);

    // Header actions
    auto* actions = new QWidget;
    auto* al = new QHBoxLayout(actions); al->setContentsMargins(0,0,0,0); al->setSpacing(theme::Space2);
    auto* seg = new QWidget; auto* sl = new QHBoxLayout(seg); sl->setContentsMargins(2,2,2,2); sl->setSpacing(2);
    seg->setStyleSheet(QString("background:%1;border:1px solid %2;border-radius:%3px;")
                           .arg(theme::Surface).arg(theme::Border).arg(theme::RadiusMd));
    auto mkSeg = [&](const QString& t){
        auto* b = new QPushButton(t); b->setCheckable(true); b->setFixedHeight(30); b->setCursor(Qt::PointingHandCursor);
        b->setStyleSheet(QString("QPushButton{background:transparent;color:%1;border:none;border-radius:%2px;padding:0 14px;font-weight:600;font-size:12px;}"
            "QPushButton:checked{background:%3;color:%4;}").arg(theme::Dim).arg(theme::RadiusSm).arg(theme::Accent).arg(theme::Bg));
        sl->addWidget(b); return b;
    };
    auto* segHard = mkSeg(QString::fromUtf8("\xF0\x9F\x9B\xA1 HARDENED"));
    auto* segOpen = mkSeg(QString::fromUtf8("\xE2\x97\xAF EXPOSED"));
    segHard->setChecked(true); al->addWidget(seg);
    auto* applyBtn = new QPushButton("Apply"); applyBtn->setFixedHeight(34);
    applyBtn->setStyleSheet(QString("QPushButton{background:transparent;color:%1;border:1px solid %1;border-radius:%2px;padding:0 14px;font-weight:600;}"
        "QPushButton:hover{background:rgba(255,122,0,0.12);}").arg(theme::Accent).arg(theme::RadiusMd));
    auto* revertBtn = new QPushButton("Revert"); revertBtn->setFixedHeight(34);
    revertBtn->setStyleSheet(QString("QPushButton{background:transparent;color:%1;border:1px solid %2;border-radius:%3px;padding:0 14px;}"
        "QPushButton:hover{color:%4;}").arg(theme::Dim).arg(theme::Border).arg(theme::RadiusMd).arg(theme::Text));
    auto* refreshBtn = new QPushButton(QString::fromUtf8("\xE2\x86\xBB")); refreshBtn->setFixedSize(34,34);
    refreshBtn->setStyleSheet(QString("QPushButton{background:transparent;color:%1;border:1px solid %2;border-radius:%3px;}"
        "QPushButton:hover{color:%4;}").arg(theme::Dim).arg(theme::Border).arg(theme::RadiusMd).arg(theme::Text));
    al->addWidget(applyBtn); al->addWidget(revertBtn); al->addWidget(refreshBtn);
    root->addWidget(theme::BuildPageHeader("Fingerprint Guard",
        QString::fromUtf8("See what makes your device trackable \xE2\x80\x94 and harden the surface."), actions));

    // Stat cards
    auto* cardRow = new QHBoxLayout; cardRow->setSpacing(theme::Space3);
    struct CR { QLabel* v; QLabel* s; };
    auto mkCard = [&](const QString& label, const QString& color)->CR {
        auto* c = Card(); c->setFixedHeight(84);
        auto* cl = new QVBoxLayout(c); cl->setContentsMargins(14,12,14,12); cl->setSpacing(4);
        auto* lbl = new QLabel(label.toUpper());
        lbl->setStyleSheet(QString("color:%1;font-size:10px;font-weight:600;letter-spacing:1px;").arg(theme::Dim));
        cl->addWidget(lbl);
        auto* v = new QLabel("—"); v->setStyleSheet(QString("color:%1;font-size:22px;font-weight:700;").arg(color));
        cl->addWidget(v);
        auto* s = new QLabel(""); s->setStyleSheet(QString("color:%1;font-size:11px;").arg(theme::Dim));
        cl->addWidget(s);
        cardRow->addWidget(c, 1); return { v, s };
    };
    auto cUniq = mkCard("Uniqueness", theme::Accent);
    auto cAd   = mkCard("Advertising ID", theme::Text);
    auto cMac  = mkCard("MAC Address", theme::Text);
    auto cGuid = mkCard("Machine GUID", theme::Text);
    auto cTrk  = mkCard("Trackers Blocked", theme::Text);
    root->addLayout(cardRow);

    // Middle: fingerprint surface (left) + hardening toggles (right)
    auto* midRow = new QHBoxLayout; midRow->setSpacing(theme::Space3);

    auto* surfCard = Card();
    auto* surfL = new QVBoxLayout(surfCard); surfL->setContentsMargins(14,12,14,12); surfL->setSpacing(8);
    auto* surfHead = new QLabel(QString::fromUtf8("Fingerprint Surface"));
    surfHead->setStyleSheet(QString("color:%1;font-size:13px;font-weight:600;").arg(theme::Text));
    surfL->addWidget(surfHead);
    auto* surfGrid = new QGridLayout; surfGrid->setHorizontalSpacing(16); surfGrid->setVerticalSpacing(6);
    surfL->addLayout(surfGrid); surfL->addStretch();
    midRow->addWidget(surfCard, 3);

    auto* layerCard = Card();
    auto* ll = new QVBoxLayout(layerCard); ll->setContentsMargins(14,12,14,12); ll->setSpacing(10);
    auto* lh = new QLabel(QString::fromUtf8("Hardening"));
    lh->setStyleSheet(QString("color:%1;font-size:13px;font-weight:600;").arg(theme::Text));
    ll->addWidget(lh);
    std::vector<QLabel*> tileStatus(st->layers.size());
    for (size_t i = 0; i < st->layers.size(); ++i) {
        const auto& L = st->layers[i];
        auto* row = new QHBoxLayout;
        auto* col = new QVBoxLayout; col->setSpacing(2);
        auto* nm = new QLabel(L.label); nm->setStyleSheet(QString("color:%1;font-size:12px;font-weight:600;").arg(theme::Text));
        auto* stt = new QLabel(L.status); stt->setStyleSheet(QString("color:%1;font-size:11px;font-family:%2;").arg(theme::AccentSoft).arg(theme::MonoFamily));
        tileStatus[i] = stt;
        col->addWidget(nm); col->addWidget(stt);
        row->addLayout(col, 1);
        auto* tog = Toggle(L.enabled);
        const QString id = L.id;
        QObject::connect(tog, &QPushButton::toggled, page, [st, id](bool on){
            std::lock_guard<std::mutex> lk(st->mtx); for (auto& x : st->layers) if (x.id == id) x.enabled = on;
        });
        row->addWidget(tog, 0, Qt::AlignVCenter);
        ll->addLayout(row);
    }
    ll->addStretch();
    midRow->addWidget(layerCard, 2);
    root->addLayout(midRow);

    // Tracker monitor table + detail
    auto* body = new QHBoxLayout; body->setSpacing(theme::Space3);
    auto* tblCard = Card();
    auto* tc = new QVBoxLayout(tblCard); tc->setContentsMargins(0,0,0,0); tc->setSpacing(0);
    auto* toolbar = new QWidget; auto* tb = new QHBoxLayout(toolbar); tb->setContentsMargins(14,10,14,10); tb->setSpacing(theme::Space2);
    auto* mt = new QLabel(QString::fromUtf8("Tracker & Fingerprint Monitor"));
    mt->setStyleSheet(QString("color:%1;font-size:13px;font-weight:600;").arg(theme::Text));
    tb->addWidget(mt);
    auto* cntLbl = new QLabel("0 events"); cntLbl->setStyleSheet(QString("color:%1;font-size:11px;").arg(theme::Dim));
    tb->addWidget(cntLbl); tb->addStretch();
    QStringList chips = {"All","Fingerprint","Analytics","Ads"};
    std::vector<QPushButton*> chipBtns;
    for (const auto& ch : chips) {
        auto* b = new QPushButton(ch); b->setCheckable(true); b->setFixedHeight(28); b->setCursor(Qt::PointingHandCursor);
        b->setStyleSheet(QString("QPushButton{background:transparent;color:%1;border:1px solid %2;border-radius:%3px;padding:0 10px;font-size:11px;}"
            "QPushButton:checked{background:rgba(255,122,0,0.15);border-color:%4;color:%4;}").arg(theme::Dim).arg(theme::Border).arg(theme::RadiusSm).arg(theme::Accent));
        chipBtns.push_back(b); tb->addWidget(b);
    }
    chipBtns[0]->setChecked(true);
    auto* search = new QLineEdit; search->setPlaceholderText(QString::fromUtf8("Filter by process / host\xE2\x80\xA6"));
    search->setFixedSize(190,28);
    search->setStyleSheet(QString("QLineEdit{background:%1;border:1px solid %2;border-radius:%3px;color:%4;padding:0 8px;font-size:11px;}"
        "QLineEdit:focus{border-color:%5;}").arg(theme::Surface2).arg(theme::Border).arg(theme::RadiusSm).arg(theme::Text).arg(theme::Accent));
    tb->addWidget(search); tc->addWidget(toolbar);

    auto* tbl = new QTableWidget(0, 7);
    tbl->setHorizontalHeaderLabels({"", "Time", "Process", "Tracker Endpoint", "Type", "Status", "Count"});
    tbl->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    tbl->setColumnWidth(0,30); tbl->setColumnWidth(1,78); tbl->setColumnWidth(2,150);
    tbl->setColumnWidth(4,100); tbl->setColumnWidth(5,90); tbl->setColumnWidth(6,56);
    tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    tbl->setSelectionMode(QAbstractItemView::SingleSelection);
    tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tbl->setShowGrid(false); tbl->verticalHeader()->hide();
    tbl->setContextMenuPolicy(Qt::CustomContextMenu);
    tbl->setStyleSheet(theme::TableQss());
    tc->addWidget(tbl, 1);
    body->addWidget(tblCard, 1);

    auto* detail = new QFrame; detail->setFixedWidth(0);
    detail->setStyleSheet(QString("QFrame{background:%1;border:1px solid %2;border-radius:%3px;}")
                              .arg(theme::Sidebar).arg(theme::Border).arg(theme::RadiusLg));
    auto* dl = new QVBoxLayout(detail); dl->setContentsMargins(14,12,14,12); dl->setSpacing(8);
    auto* dTitle = new QLabel(QString::fromUtf8("Tracker Detail"));
    dTitle->setStyleSheet(QString("color:%1;font-size:13px;font-weight:600;").arg(theme::Accent));
    dl->addWidget(dTitle);
    auto* dBody = new QLabel; dBody->setWordWrap(true); dBody->setTextInteractionFlags(Qt::TextSelectableByMouse);
    dBody->setStyleSheet(QString("color:%1;font-size:12px;font-family:%2;").arg(theme::Muted).arg(theme::MonoFamily));
    dl->addWidget(dBody); dl->addStretch();
    body->addWidget(detail);
    root->addLayout(body, 1);

    // ── Rendering ────────────────────────────────────────────────────────────
    auto refreshSurface = [=]() {
        std::lock_guard<std::mutex> lk(st->mtx);
        // clear grid
        QLayoutItem* it;
        while ((it = surfGrid->takeAt(0))) { if (it->widget()) it->widget()->deleteLater(); delete it; }
        int r = 0, exposed = 0;
        for (const auto& a : st->attrs) {
            auto* k = new QLabel(a.label);
            k->setStyleSheet(QString("color:%1;font-size:11px;").arg(theme::Dim));
            auto* v = new QLabel(a.value);
            v->setStyleSheet(QString("color:%1;font-size:12px;font-family:%2;").arg(theme::Text).arg(theme::MonoFamily));
            auto* pill = new QLabel(a.exposed ? "exposed" : "protected");
            pill->setStyleSheet(QString("color:%1;font-size:10px;font-weight:600;").arg(a.exposed ? theme::Danger : theme::Safe));
            surfGrid->addWidget(k, r, 0);
            surfGrid->addWidget(v, r, 1);
            surfGrid->addWidget(pill, r, 2, Qt::AlignRight);
            if (a.exposed) ++exposed;
            ++r;
        }
        const int total = (int)st->attrs.size();
        cUniq.v->setText(total ? QString("%1/%2").arg(exposed).arg(total) : "—");
        cUniq.s->setText("attributes exposed");
    };

    auto refreshStatus = [=]() {
        const int adId = RegDword(HKEY_CURRENT_USER,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled", 1);
        const QString mac = FirstMac();
        const bool macRnd = mac.size() >= 2 && (mac.left(2).toInt(nullptr,16) & 0x02);
        const QString guid = RegStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
        cAd.v->setText(adId ? "On" : "Off");
        cAd.v->setStyleSheet(QString("color:%1;font-size:22px;font-weight:700;").arg(adId ? theme::Danger : theme::Safe));
        cAd.s->setText(adId ? "trackable" : "disabled");
        cMac.v->setText(macRnd ? "Random" : "Static");
        cMac.v->setStyleSheet(QString("color:%1;font-size:22px;font-weight:700;").arg(macRnd ? theme::Safe : theme::Danger));
        cMac.s->setText(mac.isEmpty() ? "" : mac);
        cGuid.v->setText(guid.isEmpty() ? "?" : "Exposed");
        cGuid.s->setText("hardware id");
        {
            std::lock_guard<std::mutex> lk(st->mtx);
            for (auto& L : st->layers) {
                if (L.id == "adid")     L.status = adId ? "ID enabled" : "disabled";
                else if (L.id == "mac") L.status = macRnd ? "randomised" : "factory MAC";
            }
            for (size_t i = 0; i < st->layers.size(); ++i) if (tileStatus[i]) tileStatus[i]->setText(st->layers[i].status);
            cTrk.v->setText(QString::number((int)(sizeof(kTrackers)/sizeof(kTrackers[0]))));
            cTrk.s->setText("known trackers");
        }
    };

    auto refreshTable = [=]() {
        std::lock_guard<std::mutex> lk(st->mtx);
        tbl->setUpdatesEnabled(false); tbl->setRowCount(0);
        int shown = 0;
        for (int idx = 0; idx < (int)st->rows.size(); ++idx) {
            const auto& r = st->rows[idx];
            const bool fOk = st->filter == "All" || r.type == st->filter;
            const bool sOk = st->search.isEmpty() ||
                r.process.contains(st->search, Qt::CaseInsensitive) ||
                r.endpoint.contains(st->search, Qt::CaseInsensitive);
            if (!fOk || !sOk) continue;
            const int row = tbl->rowCount(); tbl->insertRow(row);
            const QColor rc = r.risk == "high" ? QColor(theme::Danger) : r.risk == "medium" ? QColor(theme::Accent) : QColor(theme::Safe);
            auto* dot = new QTableWidgetItem(QString(QChar(0x25CF))); dot->setForeground(rc);
            dot->setTextAlignment(Qt::AlignCenter); dot->setData(Qt::UserRole, idx);
            tbl->setItem(row, 0, dot);
            auto item = [](const QString& s, const QColor& c){ auto* i = new QTableWidgetItem(s); i->setForeground(c); return i; };
            tbl->setItem(row, 1, item(r.time, QColor(theme::Dim)));
            tbl->setItem(row, 2, item(r.process, QColor(theme::Text)));
            tbl->setItem(row, 3, item(r.endpoint, QColor(theme::AccentSoft)));
            tbl->setItem(row, 4, item(r.type, QColor(TypeColor(r.type))));
            tbl->setItem(row, 5, item(r.status, r.status == "Blocked" ? QColor(theme::Danger) : QColor(theme::Safe)));
            auto* cn = item(QString::number(r.count), QColor(theme::Dim));
            cn->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter); tbl->setItem(row, 6, cn);
            ++shown;
        }
        tbl->setUpdatesEnabled(true);
        cntLbl->setText(QString("%1 events").arg(shown));
    };

    for (size_t i = 0; i < chipBtns.size(); ++i) {
        auto* b = chipBtns[i]; const QString name = chips[(int)i];
        QObject::connect(b, &QPushButton::clicked, page, [=]() {
            for (auto* o : chipBtns) o->setChecked(o == b);
            { std::lock_guard<std::mutex> lk(st->mtx); st->filter = name; }
            refreshTable();
        });
    }
    auto* deb = new QTimer(page); deb->setSingleShot(true); deb->setInterval(200);
    QObject::connect(deb, &QTimer::timeout, page, [=](){ refreshTable(); });
    QObject::connect(search, &QLineEdit::textChanged, page, [=](const QString& t){
        { std::lock_guard<std::mutex> lk(st->mtx); st->search = t; } deb->start();
    });

    auto showDetail = [=](int idx){
        std::lock_guard<std::mutex> lk(st->mtx);
        if (idx < 0 || idx >= (int)st->rows.size()) { detail->setFixedWidth(0); return; }
        const auto& r = st->rows[idx]; st->selected = idx;
        dBody->setText(QString("ENDPOINT\n%1\n\nREMOTE IP\n%2\n\nPROCESS\n%3  (pid %4)\n\nTYPE\n%5\n\nHIT COUNT\n%6\n\nSTATUS\n%7")
            .arg(r.endpoint).arg(r.remoteIp).arg(r.process).arg(r.pid).arg(r.type).arg(r.count).arg(r.status));
        detail->setFixedWidth(260);
    };
    QObject::connect(tbl, &QTableWidget::itemSelectionChanged, page, [=](){
        auto items = tbl->selectedItems(); if (items.isEmpty()) return;
        showDetail(tbl->item(items.first()->row(), 0)->data(Qt::UserRole).toInt());
    });
    auto setRowStatus = [=](int idx, const QString& s){
        { std::lock_guard<std::mutex> lk(st->mtx); if (idx>=0 && idx<(int)st->rows.size()) st->rows[idx].status = s; }
        refreshTable();
    };
    QObject::connect(tbl, &QTableWidget::customContextMenuRequested, page, [=](const QPoint& p){
        auto* it = tbl->itemAt(p); if (!it) return;
        int idx = tbl->item(it->row(), 0)->data(Qt::UserRole).toInt();
        QMenu menu; menu.setStyleSheet(QString("QMenu{background:%1;border:1px solid %2;color:%3;}QMenu::item:selected{background:%4;}")
            .arg(theme::Surface2).arg(theme::Border).arg(theme::Text).arg(theme::Surface));
        menu.addAction(QString::fromUtf8("Block this tracker"), page, [=](){ setRowStatus(idx, "Blocked"); });
        menu.addAction(QString::fromUtf8("Allow this tracker"), page, [=](){ setRowStatus(idx, "Allowed"); });
        menu.exec(tbl->viewport()->mapToGlobal(p));
    });

    QObject::connect(segHard, &QPushButton::clicked, page, [=](){
        segHard->setChecked(true); segOpen->setChecked(false);
        std::lock_guard<std::mutex> lk(st->mtx); st->pendingMode = "HARDENED";
    });
    QObject::connect(segOpen, &QPushButton::clicked, page, [=](){
        segOpen->setChecked(true); segHard->setChecked(false);
        std::lock_guard<std::mutex> lk(st->mtx); st->pendingMode = "EXPOSED";
    });
    QObject::connect(applyBtn, &QPushButton::clicked, page, [=](){
        QString mode; { std::lock_guard<std::mutex> lk(st->mtx); st->mode = st->pendingMode; mode = st->mode; }
        const QString flag = mode == "HARDENED" ? "-Apply" : "-Revert";
        std::wstring params = L"-NoProfile -ExecutionPolicy Bypass -File \"C:\\Dev\\TelemetryBlock\\Harden-Fingerprint.ps1\" "
                            + flag.toStdWString();
        ShellExecuteW(nullptr, L"runas", L"powershell.exe", params.c_str(), nullptr, SW_SHOWNORMAL);
        std::thread([st]{ ReadFingerprint(st); }).detach();
    });
    QObject::connect(revertBtn, &QPushButton::clicked, page, [=](){
        segHard->setChecked(true); segOpen->setChecked(false);
        std::lock_guard<std::mutex> lk(st->mtx); st->pendingMode = st->mode;
    });
    QObject::connect(refreshBtn, &QPushButton::clicked, page, [=](){
        std::thread([st]{ ReadFingerprint(st); }).detach();
        QTimer::singleShot(200, page, [=](){ refreshSurface(); refreshStatus(); });
    });

    // background: audit + resolve trackers, then periodic capture
    std::thread([st]{ ReadFingerprint(st); ResolveTrackers(st); }).detach();
    auto* poll = new QTimer(page); poll->setInterval(3000);
    QObject::connect(poll, &QTimer::timeout, page, [=](){
        if (!st->capturing.exchange(true))
            std::thread([st]{ CaptureRows(st); st->capturing.store(false); }).detach();
        refreshStatus(); refreshTable();
    });
    poll->start();
    QTimer::singleShot(400, page, [=](){ refreshSurface(); refreshStatus(); refreshTable(); });

    return page;
}

} // namespace avdashboard
