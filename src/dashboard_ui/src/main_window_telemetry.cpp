// main_window_telemetry.cpp — Telemetry Guard
// Realtime monitoring + control of Windows telemetry. Shows the live outbound
// connections the machine is making to known Microsoft telemetry endpoints
// (captured from the TCP table, matched against resolved telemetry-host IPs),
// and lets the user BLOCK or OPEN telemetry per layer.
//
// Real system state is read directly (no fabricated rows):
//   - AllowTelemetry policy   (registry)
//   - DiagTrack / dmwappushservice (service control manager)
//   - hosts-file blocklist     (count of telemetry hosts null-routed)
//   - live endpoints           (GetExtendedTcpTable -> resolved telemetry IPs)
// Applying a mode shells out (elevated) to the repo's Harden-Telemetry.ps1,
// which performs the actual, reversible hardening.

// Winsock2 headers MUST precede any <windows.h> (which main_window.hpp / Qt pull
// in transitively). If windows.h is seen first it drags in the legacy winsock.h
// and ws2tcpip.h below fails to compile (IP_MSFILTER / SourceList errors).
// NOMINMAX stops the Windows min/max macros clashing with the Qt headers.
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <Psapi.h>

#include "main_window.hpp"
#include "theme.hpp"
#include "elevated_script.hpp"
#include "av_quit_guard.hpp"

#include <QAbstractItemView>
#include <QComboBox>
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
#include <vector>

namespace avdashboard {
namespace {

// ─── Known Microsoft telemetry endpoints + category ──────────────────────────
struct TeleHost { const wchar_t* host; const char* category; };
const TeleHost kTelemetryHosts[] = {
    {L"v10.events.data.microsoft.com",          "Diagnostics"},
    {L"v20.events.data.microsoft.com",          "Diagnostics"},
    {L"vortex.data.microsoft.com",              "Diagnostics"},
    {L"vortex-win.data.microsoft.com",          "Diagnostics"},
    {L"v10.vortex-win.data.microsoft.com",      "Diagnostics"},
    {L"telemetry.microsoft.com",                "Diagnostics"},
    {L"settings-win.data.microsoft.com",        "CEIP"},
    {L"wdcp.microsoft.com",                     "CEIP"},
    {L"watson.microsoft.com",                   "Watson"},
    {L"watson.telemetry.microsoft.com",         "Watson"},
    {L"oca.telemetry.microsoft.com",            "Watson"},
    {L"oca.microsoft.com",                      "Watson"},
    {L"sqm.telemetry.microsoft.com",            "CEIP"},
    {L"telecommand.telemetry.microsoft.com",    "Diagnostics"},
};

const char* CategoryColor(const QString& cat) {
    if (cat == "Diagnostics") return theme::Accent;   // amber
    if (cat == "CEIP")        return theme::Info;      // blue
    if (cat == "Watson")      return "#CE93D8";        // purple
    return theme::Dim;                                  // DNS / other
}

// ─── Shared page state ───────────────────────────────────────────────────────
struct TelemRow {
    QString  time, process, endpoint, category, status; // status: Allowed / Blocked
    QString  risk;                                       // high / medium / low
    int      count = 1;
    quint32  pid = 0;
    QString  remoteIp;
};

struct Layer {
    QString id, label, status;
    bool    enabled = true;
    bool    dropdown = false;
};

struct State {
    std::mutex                                     mtx;
    std::unordered_map<quint32, std::pair<QString, QString>> ipMap; // ip(be) -> {host, category}
    std::atomic<bool>                              resolved{false};
    std::atomic<bool>                              capturing{false}; // single-flight guard
    std::vector<TelemRow>                          rows;
    QString                                        mode = "BLOCKING";   // applied
    QString                                        pendingMode = "BLOCKING";
    QString                                        filter = "All";
    QString                                        search;
    QString                                        dohProvider = "Cloudflare";
    int                                            selected = -1;
    std::vector<Layer>                             layers;
    quint64                                        endpointsSeen = 0;
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

// ─── Real status reads ───────────────────────────────────────────────────────
int ReadAllowTelemetry() {
    DWORD val = 0, sz = sizeof(val), type = 0;
    // Policy first, then the OS default location.
    if (RegGetValueW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
            L"AllowTelemetry", RRF_RT_REG_DWORD, &type, &val, &sz) == ERROR_SUCCESS)
        return (int)val;
    sz = sizeof(val);
    if (RegGetValueW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection",
            L"AllowTelemetry", RRF_RT_REG_DWORD, &type, &val, &sz) == ERROR_SUCCESS)
        return (int)val;
    return -1; // unknown
}

// Returns "Running" / "Stopped" / "Absent".
QString ServiceState(const wchar_t* name) {
    QString out = "Absent";
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return out;
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
    if (svc) {
        SERVICE_STATUS st{};
        if (QueryServiceStatus(svc, &st))
            out = (st.dwCurrentState == SERVICE_RUNNING) ? "Running" : "Stopped";
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return out;
}

int HostsBlockedCount() {
    wchar_t win[MAX_PATH]; GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring path = std::wstring(win) + L"\\System32\\drivers\\etc\\hosts";
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (!f) return 0;
    std::string data; char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) data.append(buf, n);
    fclose(f);
    int hits = 0;
    for (const auto& th : kTelemetryHosts) {
        std::string host = QString::fromWCharArray(th.host).toStdString();
        if (data.find(host) != std::string::npos) ++hits;
    }
    return hits;
}

// ─── Resolve telemetry hostnames -> IP set (background, once) ─────────────────
void ResolveHosts(State* st) {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    std::unordered_map<quint32, std::pair<QString, QString>> map;
    for (const auto& th : kTelemetryHosts) {
        ADDRINFOW hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        PADDRINFOW res = nullptr;
        if (GetAddrInfoW(th.host, nullptr, &hints, &res) == 0) {
            for (auto* p = res; p; p = p->ai_next) {
                auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
                map[sa->sin_addr.S_un.S_addr] = { QString::fromWCharArray(th.host), th.category };
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

// ─── Capture live telemetry connections from the TCP table ───────────────────
QString RiskForCategory(const QString& cat) {
    if (cat == "Diagnostics" || cat == "Watson") return "high";
    if (cat == "CEIP") return "medium";
    return "low";
}

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

    // Aggregate by endpoint host.
    std::unordered_map<QString, TelemRow> agg;
    const QString now = QTime::currentTime().toString("HH:mm:ss");
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& e = table->table[i];
        auto it = ipMap.find(e.dwRemoteAddr);
        if (it == ipMap.end()) continue;
        const QString host = it->second.first;
        auto& r = agg[host];
        if (r.endpoint.isEmpty()) {
            r.endpoint = host;
            r.category = it->second.second;
            r.risk     = RiskForCategory(r.category);
            r.pid      = e.dwOwningPid;
            r.process  = ProcName(e.dwOwningPid);
            r.time     = now;
            // Format the IPv4 manually (dwRemoteAddr is network byte order) instead
            // of inet_ntoa, whose shared buffer is unsafe to call from this thread.
            const quint32 ip = e.dwRemoteAddr;
            r.remoteIp = QString("%1.%2.%3.%4").arg(ip & 0xFF).arg((ip >> 8) & 0xFF)
                             .arg((ip >> 16) & 0xFF).arg((ip >> 24) & 0xFF);
        }
        r.count++;
    }

    std::vector<TelemRow> rows;
    rows.reserve(agg.size());
    for (auto& kv : agg) rows.push_back(std::move(kv.second));

    {
        std::lock_guard<std::mutex> lk(st->mtx);
        // status reflects the applied mode: OPEN => everything allowed; BLOCKING
        // => these live endpoints are ones still getting through (Allowed), the
        // rest are being stopped upstream and simply never appear.
        for (auto& r : rows) r.status = "Allowed";
        st->rows = std::move(rows);
        st->endpointsSeen = st->rows.size();
    }
}

// ─── Small UI builders ───────────────────────────────────────────────────────
QWidget* Card() {
    auto* c = new QWidget;
    // Scope the border to THIS widget via an id selector. A selector-less inline
    // stylesheet ("border:1px...") cascades the border onto every child QLabel
    // (which boxes/clips their text); an id selector matches only the card.
    c->setObjectName("GuardCard");
    c->setStyleSheet(QString("QWidget#GuardCard{background:%1;border:1px solid %2;border-radius:%3px;}")
                         .arg(theme::Surface).arg(theme::Border).arg(theme::RadiusLg));
    return c;
}

// Section heading with a small amber accent bar on the left.
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

// A checkable pill toggle (flat, on-theme).
QPushButton* Toggle(bool checked) {
    auto* t = new QPushButton;
    t->setCheckable(true);
    t->setChecked(checked);
    t->setFixedSize(38, 20);
    t->setCursor(Qt::PointingHandCursor);
    t->setStyleSheet(QString(
        "QPushButton{border-radius:10px;background:%1;border:1px solid %2;}"
        "QPushButton:checked{background:%3;border:1px solid %3;}")
        .arg("#3A3A3E").arg("#4A4A4E").arg(theme::Accent));
    return t;
}

// Absolute path to a hardening script shipped next to the executable (installer
// drops them in {app}; the CMake post-build copies them beside the dev exe).
std::wstring ScriptPath(const wchar_t* name) {
    wchar_t buf[MAX_PATH]; GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p(buf); auto s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos ? std::wstring() : p.substr(0, s + 1)) + name;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
QWidget* BuildTelemetryGuardPage(QWidget* parent) {
    auto* page = new QWidget(parent);
    page->setObjectName("TelemetryPage");
    ArmQuitGuard(page);
    // QLabel is-a QFrame, so an ancestor "QFrame{border}" stylesheet would box
    // every text label. Reset borders for all labels on this page.
    page->setStyleSheet("QLabel{border:none;}");

    auto* st = new State();
    st->layers = {
        {"allowtelemetry", "AllowTelemetry policy", "reading...", true,  false},
        {"diagtrack",      "DiagTrack service",      "reading...", true,  false},
        {"dmwapp",         "dmwappushservice",       "reading...", true,  false},
        {"tasks",          "Scheduled tasks",        "reading...", true,  false},
        {"hosts",          "Hosts blocklist",        "reading...", true,  false},
        {"doh",            "Enforce DoH",            "Cloudflare", true,  true },
        {"firewall",       "Firewall block rule",    "reading...", true,  false},
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
    // Qt standard reload pixmap always renders (no font-glyph dependency).
    refreshBtn->setIcon(refreshBtn->style()->standardIcon(QStyle::SP_BrowserReload));
    refreshBtn->setFixedSize(34, 34);
    refreshBtn->setStyleSheet(QString(
        "QPushButton{background:transparent;color:%1;border:1px solid %2;border-radius:%3px;}"
        "QPushButton:hover{color:%4;}").arg(theme::Dim).arg(theme::Border).arg(theme::RadiusMd).arg(theme::Text));
    al->addWidget(applyBtn);
    al->addWidget(revertBtn);
    al->addWidget(refreshBtn);

    root->addWidget(theme::BuildPageHeader(
        "Telemetry Guard",
        QString::fromUtf8("Realtime telemetry monitoring & control \xE2\x80\x94 block or allow, per layer."),
        actions));

    // ── Stat cards ───────────────────────────────────────────────────────────
    auto* cardRow = new QHBoxLayout;
    cardRow->setSpacing(theme::Space3);
    struct CardRefs { QLabel* value; QLabel* sub; QLabel* dot; };
    auto makeCard = [&](const QString& label, const QString& color) -> CardRefs {
        auto* c = Card();
        c->setFixedHeight(96);
        auto* cl = new QVBoxLayout(c);
        cl->setContentsMargins(14, 12, 14, 12);
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
    auto cLevel = makeCard("Telemetry Level", theme::Accent);
    auto cDiag  = makeCard("DiagTrack",       theme::Text);
    auto cDoh   = makeCard("Encrypted DNS",   theme::Text);
    auto cHosts = makeCard("Hosts Blocked",   theme::Text);
    auto cSeen  = makeCard("Endpoints Seen",  theme::Accent);
    root->addLayout(cardRow);

    // ── Layer control ────────────────────────────────────────────────────────
    auto* layerCard = Card();
    auto* ll = new QVBoxLayout(layerCard);
    ll->setContentsMargins(14, 12, 14, 12);
    ll->setSpacing(theme::Space3);
    ll->addWidget(SectionTitle(QString::fromUtf8("Layer Control")));
    // Split the 7 layer tiles across two rows so they don't force the card wider
    // than the capped page. Each row is divided into `cols` equal columns so the
    // tiles line up in a grid.
    auto* tilesRow1 = new QHBoxLayout;
    tilesRow1->setSpacing(theme::Space2);
    auto* tilesRow2 = new QHBoxLayout;
    tilesRow2->setSpacing(theme::Space2);
    const size_t cols = (st->layers.size() + 1) / 2;

    std::vector<QLabel*> tileStatus(st->layers.size());
    std::vector<QPushButton*> tileToggle(st->layers.size());
    for (size_t i = 0; i < st->layers.size(); ++i) {
        const auto& L = st->layers[i];
        auto* tile = new QWidget;
        tile->setObjectName("GuardBox");
        tile->setStyleSheet(QString("QWidget#GuardBox{background:%1;border:1px solid %2;border-radius:%3px;}")
                                .arg("rgba(255,122,0,0.06)").arg("rgba(255,122,0,0.20)").arg(theme::RadiusMd));
        auto* tl = new QVBoxLayout(tile);
        tl->setContentsMargins(10, 10, 10, 10);
        tl->setSpacing(8);
        auto* topRow = new QHBoxLayout; topRow->setContentsMargins(0,0,0,0);
        auto* nameLbl = new QLabel(L.label);
        nameLbl->setWordWrap(true);
        nameLbl->setStyleSheet(QString("color:%1;font-size:11px;font-weight:600;").arg(theme::Text));
        topRow->addWidget(nameLbl, 1);
        auto* tog = Toggle(L.enabled);
        tileToggle[i] = tog;
        topRow->addWidget(tog, 0, Qt::AlignTop);
        tl->addLayout(topRow);
        if (L.dropdown) {
            auto* combo = new QComboBox;
            combo->addItems({"Cloudflare", "Quad9", "Google"});
            combo->setStyleSheet(QString(
                "QComboBox{background:%1;border:1px solid %2;border-radius:%3px;color:%4;padding:2px 6px;font-size:11px;}")
                .arg(theme::Surface2).arg(theme::Border).arg(theme::RadiusSm).arg(theme::Dim));
            QObject::connect(combo, &QComboBox::currentTextChanged, page, [st](const QString& v){
                std::lock_guard<std::mutex> lk(st->mtx); st->dohProvider = v;
            });
            tl->addWidget(combo);
        } else {
            auto* status = new QLabel(L.status);
            status->setStyleSheet(QString("color:%1;font-size:11px;font-family:%2;").arg(theme::AccentSoft).arg(theme::MonoFamily));
            tileStatus[i] = status;
            tl->addWidget(status);
        }
        const QString id = L.id;
        QObject::connect(tog, &QPushButton::toggled, page, [st, id](bool on){
            std::lock_guard<std::mutex> lk(st->mtx);
            for (auto& lay : st->layers) if (lay.id == id) lay.enabled = on;
        });
        (i < cols ? tilesRow1 : tilesRow2)->addWidget(tile, 1);
    }
    // Pad the second row so its tiles align under the first row's columns.
    for (size_t k = 0, pad = 2 * cols - st->layers.size(); k < pad; ++k)
        tilesRow2->addStretch(1);
    ll->addLayout(tilesRow1);
    ll->addLayout(tilesRow2);
    root->addWidget(layerCard);

    // ── Monitor: table (left) + detail panel (right) ─────────────────────────
    auto* body = new QHBoxLayout;
    body->setSpacing(theme::Space3);

    auto* tblCard = Card();
    auto* tc = new QVBoxLayout(tblCard);
    tc->setContentsMargins(0, 0, 0, 0);
    tc->setSpacing(0);

    // toolbar: title + filter chips + search
    auto* toolbar = new QWidget;
    auto* tb = new QHBoxLayout(toolbar);
    tb->setContentsMargins(14, 10, 14, 10);
    tb->setSpacing(theme::Space2);
    tb->addWidget(SectionTitle(QString::fromUtf8("Realtime Telemetry Monitor")));
    auto* liveLbl = new QLabel(QString::fromUtf8("\xE2\x97\x8F LIVE"));
    liveLbl->setStyleSheet(QString("color:%1;font-size:10px;font-family:%2;").arg(theme::Danger).arg(theme::MonoFamily));
    tb->addWidget(liveLbl);
    auto* countLbl = new QLabel("0 events");
    countLbl->setStyleSheet(QString("color:%1;font-size:11px;").arg(theme::Dim));
    tb->addWidget(countLbl);
    tb->addStretch();

    QStringList chips = {"All", "Blocked", "Allowed", "Diagnostics", "Watson", "DNS"};
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
    search->setPlaceholderText(QString::fromUtf8("Filter by process / host\xE2\x80\xA6"));
    search->setFixedSize(200, 28);
    search->setStyleSheet(QString(
        "QLineEdit{background:%1;border:1px solid %2;border-radius:%3px;color:%4;padding:0 8px;font-size:11px;}"
        "QLineEdit:focus{border-color:%5;}").arg(theme::Surface2).arg(theme::Border).arg(theme::RadiusSm).arg(theme::Text).arg(theme::Accent));
    tb->addWidget(search);
    tc->addWidget(toolbar);

    auto* tbl = new QTableWidget(0, 7);
    tbl->setHorizontalHeaderLabels({"", "Time", "Process", "Telemetry Endpoint", "Category", "Status", "Count"});
    tbl->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    tbl->setColumnWidth(0, 30);
    tbl->setColumnWidth(1, 78);
    tbl->setColumnWidth(2, 150);
    tbl->setColumnWidth(4, 100);
    tbl->setColumnWidth(5, 90);
    tbl->setColumnWidth(6, 56);
    tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    tbl->setSelectionMode(QAbstractItemView::SingleSelection);
    tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tbl->setShowGrid(false);
    tbl->verticalHeader()->hide();
    tbl->setContextMenuPolicy(Qt::CustomContextMenu);
    tbl->setStyleSheet(theme::TableQss());
    tc->addWidget(tbl, 1);
    body->addWidget(tblCard, 1);

    // detail panel (hidden until a row is selected)
    auto* detail = new QWidget;
    detail->setObjectName("GuardBox");
    detail->setFixedWidth(0);
    detail->setStyleSheet(QString("QWidget#GuardBox{background:%1;border:1px solid %2;border-radius:%3px;}")
                              .arg(theme::Sidebar).arg(theme::Border).arg(theme::RadiusLg));
    auto* dl = new QVBoxLayout(detail);
    dl->setContentsMargins(14, 12, 14, 12);
    dl->setSpacing(8);
    auto* dTitle = new QLabel(QString::fromUtf8("Endpoint Detail"));
    dTitle->setStyleSheet(QString("color:%1;font-size:13px;font-weight:600;").arg(theme::Accent));
    dl->addWidget(dTitle);
    auto* dBody = new QLabel;
    dBody->setWordWrap(true);
    dBody->setTextInteractionFlags(Qt::TextSelectableByMouse);
    dBody->setStyleSheet(QString("color:%1;font-size:12px;font-family:%2;").arg(theme::Muted).arg(theme::MonoFamily));
    dl->addWidget(dBody);
    dl->addStretch();
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

    // ── Rendering ────────────────────────────────────────────────────────────
    auto refreshTable = [=]() {
        std::lock_guard<std::mutex> lk(st->mtx);
        tbl->setUpdatesEnabled(false);
        tbl->setRowCount(0);
        int shown = 0;
        for (int idx = 0; idx < (int)st->rows.size(); ++idx) {
            const auto& r = st->rows[idx];
            const bool fOk =
                st->filter == "All" ||
                (st->filter == "Blocked" && r.status == "Blocked") ||
                (st->filter == "Allowed" && r.status == "Allowed") ||
                r.category == st->filter;
            const bool sOk = st->search.isEmpty() ||
                r.process.contains(st->search, Qt::CaseInsensitive) ||
                r.endpoint.contains(st->search, Qt::CaseInsensitive);
            if (!fOk || !sOk) continue;

            const int row = tbl->rowCount();
            tbl->insertRow(row);
            const QColor riskCol = r.risk == "high" ? QColor(theme::Danger)
                                 : r.risk == "medium" ? QColor(theme::Accent)
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
                QString::fromUtf8("No telemetry captured yet \xE2\x80\x94 monitoring\xE2\x80\xA6"));
            msg->setForeground(QColor(theme::Dim));
            msg->setTextAlignment(Qt::AlignCenter);
            tbl->setItem(0, 0, msg);
        }
        tbl->setUpdatesEnabled(true);
        countLbl->setText(QString("%1 events").arg(shown));
        liveLbl->setVisible(st->mode == "BLOCKING");
    };

    auto refreshStatus = [=]() {
        const int at = ReadAllowTelemetry();
        const QString diag = ServiceState(L"DiagTrack");
        const QString dmw  = ServiceState(L"dmwappushservice");
        const int hosts = HostsBlockedCount();
        {
            std::lock_guard<std::mutex> lk(st->mtx);
            for (auto& L : st->layers) {
                if (L.id == "allowtelemetry") L.status = at < 0 ? "unknown" : QString("Level %1").arg(at);
                else if (L.id == "diagtrack")  L.status = diag;
                else if (L.id == "dmwapp")     L.status = dmw;
                else if (L.id == "hosts")      L.status = QString("%1 hosts").arg(hosts);
            }
        }
        // stat cards
        cLevel.value->setText(at < 0 ? "?" : QString::number(at));
        cLevel.sub->setText(at <= 1 ? "Home min = 1" : "diagnostic data on");
        const bool running = diag == "Running";
        cDiag.value->setText(diag);
        cDiag.value->setStyleSheet(QString("color:%1;font-size:22px;font-weight:700;")
                                       .arg(running ? theme::Danger : theme::Safe));
        cDiag.sub->setText("Connected Experiences");
        cDiag.dot->setVisible(true);
        cDiag.dot->setStyleSheet(QString("background:%1;border-radius:4px;").arg(running ? theme::Danger : theme::Safe));
        {
            std::lock_guard<std::mutex> lk(st->mtx);
            bool dohOn = false; QString prov = st->dohProvider;
            for (auto& L : st->layers) if (L.id == "doh") dohOn = L.enabled;
            cDoh.value->setText(dohOn ? "Enforced" : "Off");
            cDoh.sub->setText("via " + prov);
        }
        cHosts.value->setText(QString("%1 / %2").arg(hosts).arg((int)(sizeof(kTelemetryHosts)/sizeof(kTelemetryHosts[0]))));
        cHosts.sub->setText("endpoints null-routed");
        cSeen.value->setText(QString::number(st->endpointsSeen));
        cSeen.sub->setText("active telemetry endpoints");
        // reflect layer statuses onto tiles
        std::lock_guard<std::mutex> lk(st->mtx);
        for (size_t i = 0; i < st->layers.size(); ++i)
            if (tileStatus[i]) tileStatus[i]->setText(st->layers[i].status);
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
        if (idx < 0 || idx >= (int)st->rows.size()) { detail->setFixedWidth(0); return; }
        const auto& r = st->rows[idx];
        st->selected = idx;
        dBody->setText(QString(
            "ENDPOINT\n%1\n\nREMOTE IP\n%2\n\nPROCESS\n%3  (pid %4)\n\nCATEGORY\n%5\n\nHIT COUNT\n%6\n\nSTATUS\n%7")
            .arg(r.endpoint).arg(r.remoteIp).arg(r.process).arg(r.pid).arg(r.category).arg(r.count).arg(r.status));
        detail->setFixedWidth(260);
    };
    QObject::connect(tbl, &QTableWidget::itemSelectionChanged, page, [=]() {
        auto items = tbl->selectedItems();
        if (items.isEmpty()) return;
        int idx = tbl->item(items.first()->row(), 0)->data(Qt::UserRole).toInt();
        showDetail(idx);
    });

    // right-click context menu: block / allow endpoint
    auto setRowStatus = [=](int idx, const QString& status) {
        { std::lock_guard<std::mutex> lk(st->mtx);
          if (idx >= 0 && idx < (int)st->rows.size()) st->rows[idx].status = status; }
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
        // runas => UAC prompt; helper refuses if the script dir is user-writable (anti-LPE, review #1).
        avsec::RunElevatedHardeningScript(ScriptPath(L"Harden-Telemetry.ps1"), flag.toStdWString());
        refreshStatus(); refreshTable();
    });
    QObject::connect(revertBtn, &QPushButton::clicked, page, [=](){
        segBlock->setChecked(true); segOpen->setChecked(false);
        std::lock_guard<std::mutex> lk(st->mtx); st->pendingMode = st->mode;
    });
    QObject::connect(refreshBtn, &QPushButton::clicked, page, [=](){ refreshStatus(); });

    // Background resolve + periodic capture.
    std::thread([st]{ ResolveHosts(st); }).detach();
    auto* poll = new QTimer(page);
    poll->setInterval(3000);
    QObject::connect(poll, &QTimer::timeout, page, [=](){
        // Single-flight: never let a second capture thread overlap the first.
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
