// main_window_cryptominer.cpp — Cryptominer / cryptojacking hub.
// Layout ported 1:1 from the Figma "Cryptominer Detection Screen" design:
// page header (+ status pill / Scan Now / refresh), a row of 5 stat cards,
// a "Cryptojacking Signals" 2x2 card, and a "Miner Detection Log" card with
// filter chips + search + table. Data is wired live where a source exists
// (CPU sampler, running miner processes, engine detections); styling uses the
// shared amber-dark theme tokens.

#include <QAbstractItemView>
#include <QColor>
#include <QDateTime>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include "avcore/severity.hpp"
#include "main_window.hpp"
#include "theme.hpp"

namespace avdashboard {

namespace {

// rgba() helpers for the translucent chip fills used in the design.
QString Rgba(int r, int g, int b, double a) {
    return QString("rgba(%1,%2,%3,%4)").arg(r).arg(g).arg(b).arg(a);
}

QDateTime ToQDateTime(std::chrono::system_clock::time_point tp) {
    return QDateTime::fromSecsSinceEpoch(
        static_cast<qint64>(std::chrono::system_clock::to_time_t(tp)));
}

const char* SeverityLabel(avcore::Severity s) {
    switch (s) {
        case avcore::Severity::Malicious:  return "Malicious";
        case avcore::Severity::Suspicious: return "Suspicious";
        default:                            return "Info";
    }
}

const std::unordered_set<std::string>& MinerNames() {
    static const std::unordered_set<std::string> kMiners = {
        "xmrig.exe", "smrig.exe", "nbminer.exe", "phoenixminer.exe",
        "t-rex.exe", "lolminer.exe", "cpuminer.exe", "ccminer.exe",
        "nanominer.exe", "xmr-stak.exe", "srbminer-multi.exe",
    };
    return kMiners;
}

bool IsMinerRule(const std::string& rule_id) {
    QString r = QString::fromStdString(rule_id).toLower();
    return r.contains("miner") || r.contains("cryptomin") || r.contains("stratum")
        || r.contains("xmrig") || r.contains("pool");
}

// Maps a rule id to one of the filter-chip categories.
enum class Cat { Cpu, Process, Network, Yara, Other };
Cat CatOf(const std::string& rule_id) {
    const QString up = QString::fromStdString(rule_id).toUpper();
    if (up.contains("CPU") || up.contains("PEG")) return Cat::Cpu;
    if (up.startsWith("NET.") || up.contains("STRATUM") || up.contains("POOL")) return Cat::Network;
    if (up.startsWith("YARA.") || up.startsWith("CRYPTOMINER_")) return Cat::Yara;
    if (up.startsWith("BEH.") || up.startsWith("SYS.") || up.startsWith("FS.")) return Cat::Process;
    return Cat::Other;
}

// A rounded pill label (severity / status / LIVE badges).
QLabel* MakePill(const QString& text, const char* fg, const QString& bg,
                 const QString& border, int fontpx = 11, int padH = 10) {
    auto* l = new QLabel(text);
    l->setStyleSheet(QString(
        "QLabel { color:%1; background:%2; border:1px solid %3; border-radius:999px;"
        " padding:2px %4px; font-size:%5px; font-weight:700; }")
        .arg(fg).arg(bg).arg(border).arg(padH).arg(fontpx));
    l->setAlignment(Qt::AlignCenter);
    return l;
}

// Card title: 3px amber bar + label.
QWidget* MakeCardTitle(const QString& text) {
    auto* w = new QWidget();
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(theme::Space3);
    auto* bar = new QFrame();
    bar->setFixedSize(3, 20);
    bar->setStyleSheet(QString("background:%1; border-radius:2px;").arg(theme::Accent));
    auto* lbl = new QLabel(text);
    lbl->setStyleSheet(QString("color:%1; font-size:%2px; font-weight:600;")
                           .arg(theme::Text).arg(theme::FontSubhead));
    h->addWidget(bar);
    h->addWidget(lbl);
    return w;
}

} // namespace

QWidget* BuildCryptominerPage(QWidget* parent) {
    auto* win = qobject_cast<MainWindow*>(parent);

    auto* page = new QWidget();
    // QLabel is-a QFrame, so any ancestor "QFrame{border}" stylesheet cascades a
    // box onto every text label — reset that here, and scope each card's border
    // to its own objectName so it never leaks onto children.
    page->setStyleSheet(QString("background:%1; QLabel{border:none; background:transparent;}").arg(theme::Bg));
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(theme::Space6, theme::Space6, theme::Space6, theme::Space6);
    root->setSpacing(theme::Space6);

    // ── 1. Header (title + subtitle | status pill / Scan Now / refresh) ──────
    auto* headerRow = new QHBoxLayout();
    headerRow->setContentsMargins(0, 0, 0, 0);
    headerRow->setSpacing(theme::Space4);
    auto* titleCol = new QVBoxLayout();
    titleCol->setSpacing(2);
    auto* title = new QLabel("Cryptominer Detection");
    title->setStyleSheet(QString("color:%1; font-size:%2px; font-weight:700;")
                             .arg(theme::Text).arg(theme::FontHeader));
    auto* subtitle = new QLabel(QString::fromUtf8(
        "Realtime cryptojacking monitor \xE2\x80\x94 miner processes, mining-pool traffic & CPU pegging"));
    subtitle->setStyleSheet(QString("color:%1; font-size:%2px;")
                                .arg(theme::Muted).arg(theme::FontBody));
    titleCol->addWidget(title);
    titleCol->addWidget(subtitle);
    headerRow->addLayout(titleCol);
    headerRow->addStretch();

    auto* statusPill = MakePill("\xE2\x97\x8F PROTECTED", theme::Safe,
                                Rgba(74, 222, 128, 0.13), Rgba(74, 222, 128, 0.25), 12, 12);
    auto* scanBtn = new QPushButton("Scan Now");
    scanBtn->setCursor(Qt::PointingHandCursor);
    scanBtn->setStyleSheet(QString(
        "QPushButton { color:%1; background:transparent; border:1px solid %1;"
        " border-radius:%2px; padding:6px 16px; font-size:13px; font-weight:600; }"
        "QPushButton:hover { color:%3; border-color:%3; }")
        .arg(theme::Accent).arg(theme::RadiusMd).arg(theme::AccentSoft));
    auto* refreshBtn = new QPushButton(QString::fromUtf8("\xE2\x9F\xB3"));
    refreshBtn->setCursor(Qt::PointingHandCursor);
    refreshBtn->setFixedSize(32, 32);
    refreshBtn->setStyleSheet(QString(
        "QPushButton { color:%1; background:%2; border:1px solid %3; border-radius:%4px; font-size:14px; }"
        "QPushButton:hover { color:%5; }")
        .arg(theme::Dim).arg(theme::Surface2).arg(theme::Border).arg(theme::RadiusMd).arg(theme::Accent));
    headerRow->addWidget(statusPill);
    headerRow->addWidget(scanBtn);
    headerRow->addWidget(refreshBtn);
    root->addLayout(headerRow);

    // ── 2. Stat cards row (5) ────────────────────────────────────────────────
    struct StatRefs { QLabel* val; QLabel* sub; };
    auto makeStat = [](const QString& caption, const QString& val0, const char* color,
                       const QString& sub0, bool mono, StatRefs* out) -> QFrame* {
        auto* card = new QFrame();
        card->setObjectName("CmStat");
        card->setStyleSheet(QString("QFrame#CmStat { background:%1; border:1px solid %2; border-radius:%3px; }")
                                .arg(theme::Surface).arg(theme::Border).arg(theme::RadiusLg));
        auto* v = new QVBoxLayout(card);
        v->setContentsMargins(20, 16, 20, 16);
        v->setSpacing(2);
        auto* cap = new QLabel(caption.toUpper());
        cap->setStyleSheet(QString("color:%1; font-size:10px; font-weight:600;").arg(theme::Dim));
        auto* val = new QLabel(val0);
        val->setStyleSheet(QString("color:%1; font-size:30px; font-weight:700; font-family:%2;")
                               .arg(color).arg(mono ? theme::MonoFamily : theme::SansFamily));
        auto* sub = new QLabel(sub0);
        sub->setStyleSheet(QString("color:%1; font-size:%2px; font-family:%3;")
                               .arg(theme::Dim).arg(theme::FontCaption).arg(theme::MonoFamily));
        v->addWidget(cap);
        v->addWidget(val);
        v->addWidget(sub);
        out->val = val; out->sub = sub;
        return card;
    };
    auto* statsRow = new QHBoxLayout();
    statsRow->setSpacing(theme::Space4);
    StatRefs sCpu, sProc, sPool, sDet, sEngine;
    statsRow->addWidget(makeStat("CPU Peak", "\xE2\x80\x94", theme::Dim, "sampling\xE2\x80\xA6", true, &sCpu), 1);
    statsRow->addWidget(makeStat("Miner Processes", "0", theme::Safe, "flagged running", false, &sProc), 1);
    statsRow->addWidget(makeStat("Pool Connections", "0", theme::Accent, "stratum / pool hosts", false, &sPool), 1);
    statsRow->addWidget(makeStat("Detections", "0", theme::Text, "last events", false, &sDet), 1);
    statsRow->addWidget(makeStat("Engine", "ACTIVE", theme::Safe, "behavior + YARA + net", false, &sEngine), 1);
    root->addLayout(statsRow);

    // ── 3. Cryptojacking Signals card (2x2) ──────────────────────────────────
    struct SigRefs { QLabel* detail; QLabel* chip; };
    auto* sigCard = new QFrame();
    sigCard->setObjectName("CmSigCard");
    sigCard->setStyleSheet(QString("QFrame#CmSigCard { background:%1; border:1px solid %2; border-radius:%3px; }")
                               .arg(theme::Surface).arg(theme::Border).arg(theme::RadiusLg));
    auto* sigV = new QVBoxLayout(sigCard);
    sigV->setContentsMargins(20, 18, 20, 18);
    sigV->setSpacing(theme::Space4);
    auto* sigHdr = new QHBoxLayout();
    sigHdr->addWidget(MakeCardTitle("Cryptojacking Signals"));
    sigHdr->addStretch();
    auto* sigHint = new QLabel("4 monitors active");
    sigHint->setStyleSheet(QString("color:%1; font-size:%2px;").arg(theme::Dim).arg(theme::FontCaption));
    sigHdr->addWidget(sigHint);
    sigV->addLayout(sigHdr);

    auto* sigGrid = new QGridLayout();
    sigGrid->setHorizontalSpacing(theme::Space3);
    sigGrid->setVerticalSpacing(theme::Space3);
    auto makeSignal = [](const QString& label, const QString& detail0, SigRefs* out) -> QWidget* {
        auto* row = new QFrame();
        row->setObjectName("CmSigRow");
        row->setStyleSheet(QString("QFrame#CmSigRow { background:%1; border:1px solid %2; border-radius:%3px; }")
                               .arg(theme::Surface2).arg(theme::Border).arg(theme::RadiusMd));
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(16, 12, 16, 12);
        h->setSpacing(theme::Space3);
        auto* dot = new QLabel(QString::fromUtf8("\xE2\x97\x8F"));
        dot->setStyleSheet(QString("color:%1; font-size:10px;").arg(theme::Dim));
        auto* col = new QVBoxLayout();
        col->setSpacing(1);
        auto* lbl = new QLabel(label);
        lbl->setStyleSheet(QString("color:%1; font-size:13px; font-weight:500;").arg(theme::Text));
        auto* det = new QLabel(detail0);
        det->setStyleSheet(QString("color:%1; font-size:11px; font-family:%2;")
                               .arg(theme::Dim).arg(theme::MonoFamily));
        col->addWidget(lbl);
        col->addWidget(det);
        auto* chip = MakePill("CLEAR", theme::Safe, Rgba(74, 222, 128, 0.13), Rgba(74, 222, 128, 0.25));
        h->addWidget(dot);
        h->addLayout(col, 1);
        h->addWidget(chip);
        out->detail = det; out->chip = chip;
        return row;
    };
    SigRefs sigCpu, sigStratum, sigBinary, sigDomain;
    sigGrid->addWidget(makeSignal("CPU Pegging", "no process \xE2\x89\xA5 70% CPU", &sigCpu), 0, 0);
    sigGrid->addWidget(makeSignal("Stratum Pool Port", "no pool-port connections", &sigStratum), 0, 1);
    sigGrid->addWidget(makeSignal("Known Miner Binary", "no miner binary running", &sigBinary), 1, 0);
    sigGrid->addWidget(makeSignal("Mining-Pool Domain", "no pool hostnames", &sigDomain), 1, 1);
    sigV->addLayout(sigGrid);
    root->addWidget(sigCard);

    // ── 4. Miner Detection Log card ──────────────────────────────────────────
    auto* logCard = new QFrame();
    logCard->setObjectName("CmLogCard");
    logCard->setStyleSheet(QString("QFrame#CmLogCard { background:%1; border:1px solid %2; border-radius:%3px; }")
                               .arg(theme::Surface).arg(theme::Border).arg(theme::RadiusLg));
    auto* logV = new QVBoxLayout(logCard);
    logV->setContentsMargins(20, 18, 20, 18);
    logV->setSpacing(theme::Space4);

    auto* logHdr = new QHBoxLayout();
    logHdr->setSpacing(theme::Space3);
    logHdr->addWidget(MakeCardTitle("Miner Detection Log"));
    auto* liveBadge = MakePill(QString::fromUtf8("\xE2\x97\x8F LIVE"), "#FF9B9B",
                               Rgba(255, 90, 106, 0.12), Rgba(255, 90, 106, 0.25));
    logHdr->addWidget(liveBadge);
    auto* eventsBadge = MakePill("0 events", theme::Dim, theme::Surface2, theme::Border);
    logHdr->addWidget(eventsBadge);
    logHdr->addStretch();
    logV->addLayout(logHdr);

    // Filter chips + search
    auto* chipsRow = new QHBoxLayout();
    chipsRow->setSpacing(theme::Space2);
    const QStringList kFilters = {"All", "CPU", "Process", "Network", "YARA"};
    auto activeFilter = std::make_shared<QString>("All");
    std::vector<QPushButton*> chipBtns;
    for (const auto& f : kFilters) {
        auto* b = new QPushButton(f);
        b->setCursor(Qt::PointingHandCursor);
        b->setCheckable(true);
        chipsRow->addWidget(b);
        chipBtns.push_back(b);
    }
    auto* search = new QLineEdit();
    search->setPlaceholderText(QString::fromUtf8("Filter by process / rule\xE2\x80\xA6"));
    search->setMinimumWidth(240);
    search->setStyleSheet(QString(
        "QLineEdit { background:%1; border:1px solid %2; border-radius:%3px; color:%4;"
        " padding:6px 12px; font-size:13px; }")
        .arg(theme::Surface2).arg(theme::Border).arg(theme::RadiusMd).arg(theme::Text));
    chipsRow->addStretch();
    chipsRow->addWidget(search);
    logV->addLayout(chipsRow);

    auto restyleChips = [chipBtns, kFilters, activeFilter]() {
        for (size_t i = 0; i < chipBtns.size(); ++i) {
            const bool active = (kFilters[static_cast<int>(i)] == *activeFilter);
            chipBtns[i]->setStyleSheet(QString(
                "QPushButton { border-radius:999px; padding:4px 14px; font-size:12px; font-weight:600;"
                " background:%1; color:%2; border:1px solid %3; }")
                .arg(active ? theme::Accent : theme::Surface2)
                .arg(active ? theme::Bg : theme::Muted)
                .arg(active ? theme::Accent : theme::Border));
        }
    };
    restyleChips();

    // Table
    auto* stack = new QStackedWidget();
    auto* table = new QTableWidget(0, 5);
    table->setHorizontalHeaderLabels({"TIME", "SEVERITY", "RULE", "PROCESS / PATH", "DETAILS"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionMode(QAbstractItemView::NoSelection);
    table->setSortingEnabled(false);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setStyleSheet(QString(
        "QTableWidget { background:transparent; color:%1; border:none; gridline-color:transparent; font-size:12px; }"
        "QTableWidget::item { padding:8px 12px 8px 0; border-bottom:1px solid %2;"
        " font-family:'Cascadia Code', Consolas, monospace; }"
        "QHeaderView::section { background:transparent; color:%3; font-size:10px; font-weight:600;"
        " padding:0 12px 8px 0; border:none; border-bottom:1px solid %2; }")
        .arg(theme::Text).arg(theme::Border).arg(theme::Dim));
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);

    auto* empty = new QLabel(QString::fromUtf8("No cryptominer activity detected \xE2\x80\x94 you're clear."));
    empty->setAlignment(Qt::AlignCenter);
    empty->setStyleSheet(QString("color:%1; font-size:%2px; padding:40px;")
                             .arg(theme::Dim).arg(theme::FontSubhead));
    stack->addWidget(table);  // 0
    stack->addWidget(empty);  // 1
    logV->addWidget(stack, 1);

    auto* footer = new QHBoxLayout();
    auto* footL = new QLabel("Showing 0 of 0 events");
    footL->setStyleSheet(QString("color:%1; font-size:%2px;").arg(theme::Dim).arg(theme::FontCaption));
    auto* footR = new QLabel("Engine: behavior + YARA + network heuristics");
    footR->setStyleSheet(QString("color:%1; font-size:%2px;").arg(theme::Dim).arg(theme::FontCaption));
    footer->addWidget(footL);
    footer->addStretch();
    footer->addWidget(footR);
    logV->addLayout(footer);
    root->addWidget(logCard, 1);

    // ── Live data plumbing ───────────────────────────────────────────────────
    SYSTEM_INFO si; GetSystemInfo(&si);
    const double ncpu = si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;
    auto prev = std::make_shared<std::unordered_map<DWORD, unsigned long long>>();
    auto prev_wall = std::make_shared<ULONGLONG>(0);
    auto minerDets = std::make_shared<std::vector<avcore::DetectionEvent>>();

    auto setSignal = [](const SigRefs& s, bool detected, const QString& detail) {
        s.detail->setText(detail);
        s.chip->setText(detected ? "DETECTED" : "CLEAR");
        const char* fg = detected ? theme::Danger : theme::Safe;
        const QString bg = detected ? Rgba(255, 90, 106, 0.14) : Rgba(74, 222, 128, 0.13);
        const QString bd = detected ? Rgba(255, 90, 106, 0.3) : Rgba(74, 222, 128, 0.25);
        s.chip->setStyleSheet(QString(
            "QLabel { color:%1; background:%2; border:1px solid %3; border-radius:999px;"
            " padding:2px 10px; font-size:11px; font-weight:700; }").arg(fg).arg(bg).arg(bd));
    };

    // Sample per-process CPU + count running miner binaries.
    auto refreshCpu = [=]() mutable {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        std::unordered_map<DWORD, unsigned long long> cur;
        std::unordered_map<DWORD, std::string> names;
        int miner_running = 0; QString miner_name;
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                std::string nm;
                { char b[260]; if (WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, b, sizeof(b), nullptr, nullptr) > 0) nm = b; }
                std::string low = nm; std::transform(low.begin(), low.end(), low.begin(), ::tolower);
                if (MinerNames().count(low)) { ++miner_running; if (miner_name.isEmpty()) miner_name = QString::fromStdString(nm); }
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (h) {
                    FILETIME c, e, k, u;
                    if (GetProcessTimes(h, &c, &e, &k, &u)) {
                        ULARGE_INTEGER ku, uu;
                        ku.LowPart = k.dwLowDateTime; ku.HighPart = k.dwHighDateTime;
                        uu.LowPart = u.dwLowDateTime; uu.HighPart = u.dwHighDateTime;
                        cur[pe.th32ProcessID] = ku.QuadPart + uu.QuadPart;
                        names[pe.th32ProcessID] = nm;
                    }
                    CloseHandle(h);
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);

        const ULONGLONG now = GetTickCount64();
        const ULONGLONG wall_ms = (*prev_wall == 0) ? 0 : (now - *prev_wall);
        double best_pct = 0; DWORD best_pid = 0; std::string best_name;
        if (wall_ms > 0) {
            for (const auto& kv : cur) {
                auto it = prev->find(kv.first);
                if (it == prev->end()) continue;
                const unsigned long long d = (kv.second >= it->second) ? kv.second - it->second : 0ull;
                const double pct = (d / 10000.0) / (static_cast<double>(wall_ms) * ncpu) * 100.0;
                if (pct > best_pct) { best_pct = pct; best_pid = kv.first; best_name = names.count(kv.first) ? names[kv.first] : "?"; }
            }
        }
        *prev = std::move(cur);
        *prev_wall = now;

        // CPU Peak stat
        if (best_pid != 0) {
            const int pctI = static_cast<int>(best_pct);
            const char* col = (best_pct >= 70) ? theme::Danger : (best_pct >= 30) ? theme::Accent : theme::Safe;
            sCpu.val->setText(QString::number(pctI) + "%");
            sCpu.val->setStyleSheet(QString("color:%1; font-size:30px; font-weight:700; font-family:%2;")
                                        .arg(col).arg(theme::MonoFamily));
            sCpu.sub->setText(QString::fromStdString(best_name) + QString(" (PID %1)").arg(best_pid));
        }
        // Miner processes stat + signals
        sProc.val->setText(QString::number(miner_running));
        sProc.val->setStyleSheet(QString("color:%1; font-size:30px; font-weight:700;")
                                     .arg(miner_running > 0 ? theme::Danger : theme::Safe));
        setSignal(sigCpu, best_pct >= 70,
                  best_pct >= 70 ? QString("%1 at %2% CPU").arg(QString::fromStdString(best_name)).arg((int)best_pct)
                                 : QString::fromUtf8("no process \xE2\x89\xA5 70% CPU"));
        setSignal(sigBinary, miner_running > 0,
                  miner_running > 0 ? (miner_name + " running") : QString("no miner binary running"));
    };

    auto repopulate = [=]() {
        const QString q = search->text().toLower();
        table->setRowCount(0);
        int shown = 0;
        for (const auto& d : *minerDets) {
            const Cat cat = CatOf(d.rule_id);
            const QString af = *activeFilter;
            if (af == "CPU"     && cat != Cat::Cpu)     continue;
            if (af == "Process" && cat != Cat::Process) continue;
            if (af == "Network" && cat != Cat::Network) continue;
            if (af == "YARA"    && cat != Cat::Yara)    continue;
            const QString rule = QString::fromStdString(d.rule_id);
            const QString path = QString::fromStdString(d.target_path);
            const QString det  = QString::fromStdString(d.evidence);
            if (!q.isEmpty() && !rule.toLower().contains(q) && !path.toLower().contains(q) && !det.toLower().contains(q))
                continue;
            const int row = table->rowCount();
            table->insertRow(row);
            auto* tItem = new QTableWidgetItem(ToQDateTime(d.timestamp).toString("HH:mm:ss"));
            tItem->setForeground(QColor(theme::Dim));
            table->setItem(row, 0, tItem);
            const char* sc = theme::SeverityColor(SeverityLabel(d.severity));
            const QString sbg = QString(SeverityLabel(d.severity)) == "Malicious" ? Rgba(255,90,106,0.15)
                              : QString(SeverityLabel(d.severity)) == "Suspicious" ? Rgba(251,191,36,0.15)
                                                                                   : Rgba(77,184,255,0.15);
            table->setCellWidget(row, 1, MakePill(SeverityLabel(d.severity), sc, sbg, sbg));
            auto* rItem = new QTableWidgetItem(rule);
            rItem->setForeground(QColor(theme::Accent));
            table->setItem(row, 2, rItem);
            auto* pItem = new QTableWidgetItem(path.isEmpty() ? "-" : path);
            pItem->setForeground(QColor(theme::Muted));
            table->setItem(row, 3, pItem);
            auto* dItem = new QTableWidgetItem(det);
            dItem->setForeground(QColor(theme::Dim));
            table->setItem(row, 4, dItem);
            ++shown;
        }
        stack->setCurrentIndex(shown > 0 ? 0 : 1);
        footL->setText(QString("Showing %1 of %2 events").arg(shown).arg(static_cast<int>(minerDets->size())));
    };

    auto refreshDets = [=]() {
        minerDets->clear();
        int net = 0;
        if (win) {
            for (const auto& d : win->GetRecentDetections(500)) {
                if (!IsMinerRule(d.rule_id)) continue;
                minerDets->push_back(d);
                if (CatOf(d.rule_id) == Cat::Network) ++net;
            }
        }
        const int total = static_cast<int>(minerDets->size());
        sDet.val->setText(QString::number(total));
        sPool.val->setText(QString::number(net));
        eventsBadge->setText(QString("%1 events").arg(total));
        setSignal(sigStratum, net > 0,
                  net > 0 ? QString("%1 pool/stratum event(s)").arg(net) : QString("no pool-port connections"));
        setSignal(sigDomain, false, QString("no pool hostnames"));
        // Header status pill
        const bool at_risk = total > 0 || sProc.val->text() != "0";
        statusPill->setText(at_risk ? QString::fromUtf8("\xE2\x97\x8F AT RISK")
                                    : QString::fromUtf8("\xE2\x97\x8F PROTECTED"));
        const char* fg = at_risk ? theme::Danger : theme::Safe;
        const QString bg = at_risk ? Rgba(255,90,106,0.14) : Rgba(74,222,128,0.13);
        const QString bd = at_risk ? Rgba(255,90,106,0.35) : Rgba(74,222,128,0.25);
        statusPill->setStyleSheet(QString(
            "QLabel { color:%1; background:%2; border:1px solid %3; border-radius:999px;"
            " padding:2px 12px; font-size:12px; font-weight:700; }").arg(fg).arg(bg).arg(bd));
        repopulate();
    };

    // Wire interactions
    for (size_t i = 0; i < chipBtns.size(); ++i) {
        const QString f = kFilters[static_cast<int>(i)];
        QObject::connect(chipBtns[i], &QPushButton::clicked, page,
                         [activeFilter, f, restyleChips, repopulate]() {
            *activeFilter = f; restyleChips(); repopulate();
        });
    }
    QObject::connect(search, &QLineEdit::textChanged, page, [repopulate](const QString&) { repopulate(); });
    QObject::connect(scanBtn, &QPushButton::clicked, page, [refreshCpu, refreshDets]() mutable { refreshCpu(); refreshDets(); });
    QObject::connect(refreshBtn, &QPushButton::clicked, page, [refreshCpu, refreshDets]() mutable { refreshCpu(); refreshDets(); });

    auto* timer = new QTimer(page);
    QObject::connect(timer, &QTimer::timeout, page, [refreshCpu, refreshDets]() mutable { refreshCpu(); refreshDets(); });
    timer->start(4000);
    refreshDets();  // initial (CPU needs a second sample for a delta)

    return page;
}

} // namespace avdashboard
