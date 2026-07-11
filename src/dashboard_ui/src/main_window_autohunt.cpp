#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <QDateTime>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QGraphicsOpacityEffect>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSizePolicy>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QWidget>

#include "avai/llm_assistant.hpp"
#include "autohunt_types.hpp"

// ─── Shared threat queue (extern visible to dllintel/syswatch) ────────────────
namespace avdashboard {

static std::mutex          g_hunt_mutex;
static std::deque<HuntTarget> g_hunt_queue;
static std::atomic<bool>   g_hunt_new_item{false};

// Called by DLL Intel / Sys Watch / Network pages to enqueue a threat
void AutoHuntEnqueue(HuntTarget t) {
    std::lock_guard<std::mutex> lk(g_hunt_mutex);
    // Deduplicate by path+source
    for (auto& existing : g_hunt_queue) {
        if (existing.path == t.path && existing.source == t.source) return;
    }
    using namespace std::chrono;
    t.detected_epoch_s = duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count();
    g_hunt_queue.push_front(std::move(t));
    if (g_hunt_queue.size() > 500) g_hunt_queue.pop_back();
    g_hunt_new_item.store(true);
}

} // namespace avdashboard

// ─── UI helpers ──────────────────────────────────────────────────────────────
namespace {

static constexpr const char* kBg     = "#120B06";
static constexpr const char* kCard   = "#1C1108";
static constexpr const char* kBorder = "#33261A";
static constexpr const char* kText   = "#ECE4DA";
static constexpr const char* kMuted  = "#8B7355";
static constexpr const char* kAccent = "#4DB8FF";
static constexpr const char* kRed    = "#FF5A6A";
static constexpr const char* kOrange = "#FF7A00";
static constexpr const char* kGreen  = "#4ADE80";

QString riskColor(int score) {
    if (score >= 75) return kRed;
    if (score >= 45) return kOrange;
    return kGreen;
}

QString riskLabel(int score) {
    if (score >= 75) return "CRITICAL";
    if (score >= 45) return "HIGH";
    if (score >= 20) return "MEDIUM";
    return "LOW";
}

QLabel* makeStatLabel(const QString& value, const QString& label, const char* color) {
    auto* w = new QWidget;
    auto* vl = new QVBoxLayout(w);
    vl->setContentsMargins(16,12,16,12);
    vl->setSpacing(4);
    auto* val = new QLabel(value);
    val->setStyleSheet(QString("color:%1;font-size:22px;font-weight:700;").arg(color));
    auto* lbl = new QLabel(label);
    lbl->setStyleSheet(QString("color:%1;font-size:11px;letter-spacing:0.5px;").arg(kMuted));
    vl->addWidget(val);
    vl->addWidget(lbl);
    w->setStyleSheet(QString("background:%1;border:1px solid %2;border-radius:8px;")
                         .arg(kCard).arg(kBorder));
    w->setObjectName("statCard_" + label);
    return nullptr; // we store val as child — caller grabs w
    (void)lbl; (void)val; // suppressed, w owns them
}

QWidget* makeStatCard(const QString& value, const QString& label,
                      const char* color, QLabel** out_val) {
    auto* w = new QWidget;
    auto* vl = new QVBoxLayout(w);
    vl->setContentsMargins(16,12,16,12);
    vl->setSpacing(4);
    auto* val = new QLabel(value);
    val->setStyleSheet(QString("color:%1;font-size:22px;font-weight:700;").arg(color));
    auto* lbl = new QLabel(label);
    lbl->setStyleSheet(QString("color:%1;font-size:11px;letter-spacing:0.5px;").arg(kMuted));
    vl->addWidget(val);
    vl->addWidget(lbl);
    w->setStyleSheet(QString("background:%1;border:1px solid %2;border-radius:8px;")
                         .arg(kCard).arg(kBorder));
    if (out_val) *out_val = val;
    return w;
}

} // anonymous namespace

// ─── Page builder ─────────────────────────────────────────────────────────────
namespace avdashboard {

QWidget* BuildAutoHuntPage(QWidget* parent, avai::LlmAssistant* ai) {
    auto* page = new QWidget(parent);
    page->setStyleSheet(QString("background:%1;").arg(kBg));

    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(20, 16, 20, 16);
    root->setSpacing(12);

    // ── Header ──────────────────────────────────────────────────────────────
    auto* autoToggle = new QCheckBox("Auto-Analyze");
    auto* huntBtn    = new QPushButton("⚡ Hunt All");
    {
        auto* hdr = new QHBoxLayout;
        hdr->setSpacing(12);

        auto* icon = new QLabel("🤖");
        icon->setStyleSheet("font-size:22px;");
        auto* title = new QLabel("AI Auto-Hunt");
        title->setStyleSheet(QString("color:%1;font-size:18px;font-weight:700;").arg(kText));
        auto* sub = new QLabel("Autonomous threat classification and investigation");
        sub->setStyleSheet(QString("color:%1;font-size:12px;").arg(kMuted));

        hdr->addWidget(icon);
        hdr->addWidget(title);
        hdr->addWidget(sub);
        hdr->addStretch();

        autoToggle->setChecked(true);
        autoToggle->setStyleSheet(QString(R"(
            QCheckBox { color:%1; font-size:12px; spacing:6px; }
            QCheckBox::indicator { width:16px; height:16px; border-radius:4px;
                                   border:1px solid %2; background:#33261A; }
            QCheckBox::indicator:checked { background:%3; border-color:%3; }
        )").arg(kText).arg(kBorder).arg(kAccent));
        hdr->addWidget(autoToggle);

        huntBtn->setStyleSheet(QString(R"(
            QPushButton { background:%1; color:white; border:none; border-radius:6px;
                          padding:6px 16px; font-size:12px; font-weight:600; }
            QPushButton:hover { background:#4DB8FF; }
        )").arg(kAccent));
        huntBtn->setCursor(Qt::PointingHandCursor);
        hdr->addWidget(huntBtn);

        root->addLayout(hdr);
    }

    // ── Stat cards ──────────────────────────────────────────────────────────
    QLabel *statTotal=nullptr, *statCritical=nullptr, *statAnalyzed=nullptr, *statPending=nullptr;
    {
        auto* row = new QHBoxLayout;
        row->setSpacing(8);
        row->addWidget(makeStatCard("0", "Total Threats",    kText,   &statTotal));
        row->addWidget(makeStatCard("0", "Critical",         kRed,    &statCritical));
        row->addWidget(makeStatCard("0", "AI Analyzed",      kGreen,  &statAnalyzed));
        row->addWidget(makeStatCard("0", "Pending",          kOrange, &statPending));
        root->addLayout(row);
    }

    // ── Body: threat table + AI panel ───────────────────────────────────────
    auto* body = new QHBoxLayout;
    body->setSpacing(12);

    // Threat table
    auto* tableCard = new QWidget;
    tableCard->setStyleSheet(QString("background:%1;border:1px solid %2;border-radius:10px;")
                                 .arg(kCard).arg(kBorder));
    auto* tableVL = new QVBoxLayout(tableCard);
    tableVL->setContentsMargins(0,0,0,0);
    tableVL->setSpacing(0);

    auto* tableHdr = new QWidget;
    tableHdr->setStyleSheet(QString("background:%1;border-bottom:1px solid %2;"
                                        "border-top-left-radius:10px;border-top-right-radius:10px;")
                                .arg(kCard).arg(kBorder));
    auto* thl = new QHBoxLayout(tableHdr);
    thl->setContentsMargins(12,8,12,8);
    auto* thlTitle = new QLabel("Threat Feed");
    thlTitle->setStyleSheet(QString("color:%1;font-size:13px;font-weight:600;").arg(kText));
    thl->addWidget(thlTitle);
    thl->addStretch();
    auto* clearBtn = new QPushButton("Clear");
    clearBtn->setStyleSheet(QString(R"(
        QPushButton { background:transparent; color:%1; border:1px solid %2;
                      border-radius:5px; padding:3px 10px; font-size:11px; }
        QPushButton:hover { background:#33261A; }
    )").arg(kMuted).arg(kBorder));
    clearBtn->setCursor(Qt::PointingHandCursor);
    thl->addWidget(clearBtn);
    tableVL->addWidget(tableHdr);

    auto* table = new QTableWidget(0, 5);
    table->setHorizontalHeaderLabels({"Source", "Name", "Risk", "Status", "Detected"});
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->verticalHeader()->setVisible(false);
    table->setAlternatingRowColors(false);
    table->setShowGrid(false);
    table->setColumnWidth(0, 90);
    table->setColumnWidth(2, 80);
    table->setColumnWidth(3, 90);
    table->setStyleSheet(QString(R"(
        QTableWidget { background:transparent; color:%1; gridline-color:%2;
                       border:none; font-size:12px; }
        QTableWidget::item { padding:8px 10px; border-bottom:1px solid %2; }
        QTableWidget::item:selected { background:#33261A; }
        QHeaderView::section { background:%3; color:%4; border:none;
                               border-bottom:1px solid %2; padding:6px 10px;
                               font-size:11px; font-weight:600; letter-spacing:0.5px; }
        QScrollBar:vertical { background:%3; width:6px; border-radius:3px; }
        QScrollBar::handle:vertical { background:%2; border-radius:3px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
    )").arg(kText).arg(kBorder).arg(kCard).arg(kMuted));
    tableVL->addWidget(table);
    body->addWidget(tableCard, 55);

    // AI analysis panel
    auto* aiCard = new QWidget;
    aiCard->setStyleSheet(QString("background:%1;border:1px solid %2;border-radius:10px;")
                              .arg(kCard).arg(kBorder));
    auto* aiVL = new QVBoxLayout(aiCard);
    aiVL->setContentsMargins(0,0,0,0);
    aiVL->setSpacing(0);

    auto* aiHdr = new QWidget;
    aiHdr->setStyleSheet(QString("background:%1;border-bottom:1px solid %2;"
                                     "border-top-left-radius:10px;border-top-right-radius:10px;")
                             .arg(kCard).arg(kBorder));
    auto* ahl = new QHBoxLayout(aiHdr);
    ahl->setContentsMargins(12,8,12,8);
    auto* aiTitle = new QLabel("AI Verdict");
    aiTitle->setStyleSheet(QString("color:%1;font-size:13px;font-weight:600;").arg(kText));
    ahl->addWidget(aiTitle);
    ahl->addStretch();
    auto* aiStatus = new QLabel("Select a threat");
    aiStatus->setStyleSheet(QString("color:%1;font-size:11px;").arg(kMuted));
    ahl->addWidget(aiStatus);
    aiVL->addWidget(aiHdr);

    // Threat info strip
    auto* threatStrip = new QWidget;
    threatStrip->setVisible(false);
    threatStrip->setStyleSheet(
        QString("background:#1C1108;border-bottom:1px solid %1;").arg(kBorder));
    auto* tsl = new QHBoxLayout(threatStrip);
    tsl->setContentsMargins(12,8,12,8);
    tsl->setSpacing(8);
    auto* stripName = new QLabel;
    stripName->setStyleSheet(QString("color:%1;font-size:12px;font-weight:600;").arg(kText));
    auto* stripRisk = new QLabel;
    stripRisk->setStyleSheet("font-size:11px;font-weight:700;padding:2px 8px;"
                             "border-radius:4px;border:1px solid transparent;");
    auto* stripPath = new QLabel;
    stripPath->setStyleSheet(QString("color:%1;font-size:10px;").arg(kMuted));
    stripPath->setTextInteractionFlags(Qt::TextSelectableByMouse);
    tsl->addWidget(stripName);
    tsl->addWidget(stripRisk);
    tsl->addStretch();
    tsl->addWidget(stripPath);
    aiVL->addWidget(threatStrip);

    // AI text area
    auto* aiText = new QTextEdit;
    aiText->setReadOnly(true);
    aiText->setStyleSheet(QString(R"(
        QTextEdit { background:transparent; color:%1; border:none;
                    font-family:'Cascadia Code',Consolas,monospace; font-size:12px;
                    padding:12px; line-height:1.6; }
        QScrollBar:vertical { background:%2; width:6px; border-radius:3px; }
        QScrollBar::handle:vertical { background:%3; border-radius:3px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
    )").arg(kText).arg(kBg).arg(kBorder));
    aiText->setPlaceholderText("Select a threat from the feed to view AI analysis.\n\n"
                               "Enable Auto-Analyze to have the AI classify threats automatically.");
    aiVL->addWidget(aiText, 1);

    // Action bar
    auto* actionBar = new QWidget;
    actionBar->setStyleSheet(
        QString("background:%1;border-top:1px solid %2;"
                "border-bottom-left-radius:10px;border-bottom-right-radius:10px;")
            .arg(kCard).arg(kBorder));
    auto* abl = new QHBoxLayout(actionBar);
    abl->setContentsMargins(12,8,12,8);
    abl->setSpacing(8);

    auto makeActBtn = [&](const QString& label, const char* bgColor) {
        auto* btn = new QPushButton(label);
        btn->setEnabled(false);
        btn->setStyleSheet(QString(R"(
            QPushButton { background:%1; color:white; border:none; border-radius:5px;
                          padding:5px 12px; font-size:11px; font-weight:600; }
            QPushButton:hover:enabled { opacity:0.85; }
            QPushButton:disabled { background:#33261A; color:%2; }
        )").arg(bgColor).arg(kMuted));
        btn->setCursor(Qt::PointingHandCursor);
        return btn;
    };
    auto* analyzeBtn  = makeActBtn("🔍 Analyze", kAccent);
    auto* killBtn     = makeActBtn("💀 Kill Process", "#FF5A6A");
    auto* quarBtn     = makeActBtn("🔒 Quarantine", "#FF7A00");
    auto* whiteBtn    = makeActBtn("✅ Whitelist", "#4ADE80");
    abl->addWidget(analyzeBtn);
    abl->addWidget(killBtn);
    abl->addWidget(quarBtn);
    abl->addWidget(whiteBtn);
    abl->addStretch();
    aiVL->addWidget(actionBar);

    body->addWidget(aiCard, 45);
    root->addLayout(body, 1);

    // ── State shared across lambdas ──────────────────────────────────────────
    struct PageState {
        int selectedRow = -1;
        bool autoAnalyze = true;
        bool aiRunning = false;
        std::vector<HuntTarget> threats;  // local copy, refreshed from g_hunt_queue
    };
    auto* state = new PageState;
    page->setProperty("pageState", QVariant::fromValue(static_cast<void*>(state)));

    // Refresh lambda: pulls from global queue into local state + updates table
    auto refreshTable = [=]() {
        std::vector<HuntTarget> snap;
        {
            std::lock_guard<std::mutex> lk(g_hunt_mutex);
            snap.assign(g_hunt_queue.begin(), g_hunt_queue.end());
        }
        state->threats = snap;

        // Update table
        table->setRowCount(static_cast<int>(snap.size()));
        int critical = 0, analyzed = 0;
        for (int r = 0; r < static_cast<int>(snap.size()); ++r) {
            const auto& t = snap[r];
            if (t.risk_score >= 75) ++critical;
            if (t.analyzed) ++analyzed;

            auto setCell = [&](int col, const QString& txt, QColor fg = QColor(kText)) {
                auto* item = new QTableWidgetItem(txt);
                item->setForeground(fg);
                table->setItem(r, col, item);
            };

            // Source badge color
            QColor srcColor(kMuted);
            if (t.source == "DLL Intel") srcColor = QColor("#4DB8FF");
            else if (t.source == "Sys Watch") srcColor = QColor(kOrange);
            else if (t.source == "Network") srcColor = QColor("#4DB8FF");

            setCell(0, QString::fromStdString(t.source), srcColor);
            setCell(1, QString::fromStdString(t.name));
            setCell(2, QString("%1 %2").arg(t.risk_score).arg(
                           QString::fromStdString(riskLabel(t.risk_score).toStdString())),
                    QColor(riskColor(t.risk_score).toStdString().c_str()));
            setCell(3, t.analyzed ? "✓ Done" : "Pending",
                    t.analyzed ? QColor(kGreen) : QColor(kOrange));

            // Timestamp
            QDateTime dt = QDateTime::fromSecsSinceEpoch(t.detected_epoch_s);
            setCell(4, dt.toString("hh:mm:ss"));

            table->setRowHeight(r, 36);
        }

        // Update stats
        if (statTotal)    statTotal->setText(QString::number(snap.size()));
        if (statCritical) statCritical->setText(QString::number(critical));
        if (statAnalyzed) statAnalyzed->setText(QString::number(analyzed));
        if (statPending)  statPending->setText(QString::number(
                              static_cast<int>(snap.size()) - analyzed));
    };

    // AI analyze lambda: calls LlmAssistant for the given threat
    auto doAnalyze = [=](int row) {
        if (!ai || state->aiRunning) return;
        if (row < 0 || row >= static_cast<int>(state->threats.size())) return;

        const HuntTarget& t = state->threats[row];
        state->aiRunning = true;
        aiStatus->setText("Analyzing...");
        aiText->clear();

        // Show threat strip
        threatStrip->setVisible(true);
        stripName->setText(QString::fromStdString(t.name));
        stripRisk->setText(QString("%1 (%2)").arg(
            QString::fromStdString(riskLabel(t.risk_score).toStdString()))
                               .arg(t.risk_score));
        stripRisk->setStyleSheet(QString("font-size:11px;font-weight:700;padding:2px 8px;"
                                         "border-radius:4px;border:1px solid %1;color:%1;")
                                     .arg(riskColor(t.risk_score)));
        stripPath->setText(QString::fromStdString(t.path));

        // Build AI prompt
        std::string system_prompt =
            "You are TeoAV's threat intelligence AI. Analyze the given threat and respond in "
            "structured format:\n"
            "VERDICT: [MALICIOUS/SUSPICIOUS/BENIGN]\n"
            "CONFIDENCE: [HIGH/MEDIUM/LOW]\n"
            "ATTACK VECTOR: [brief technical description]\n"
            "IOC INDICATORS: [list key indicators]\n"
            "RECOMMENDED ACTION: [Kill/Quarantine/Monitor/Whitelist]\n"
            "ANALYSIS: [2-3 sentence technical analysis]\n"
            "Keep response concise and actionable.";

        std::string user_msg =
            "THREAT REPORT:\n"
            "Source: " + t.source + "\n"
            "Name: " + t.name + "\n"
            "Path: " + t.path + "\n"
            "Risk Score: " + std::to_string(t.risk_score) + "/100\n"
            "Description: " + t.description + "\n"
            "Analyze this threat.";

        std::vector<avai::ChatMessage> history = {
            {"system", system_prompt},
            {"user", user_msg}
        };

        ai->GenerateAsync(std::move(history), [=](const std::string& tok, bool done) {
            QMetaObject::invokeMethod(page, [=]() {
                if (!tok.empty()) {
                    aiText->moveCursor(QTextCursor::End);
                    aiText->insertPlainText(QString::fromStdString(tok));
                    aiText->ensureCursorVisible();
                }
                if (done) {
                    state->aiRunning = false;
                    aiStatus->setText("Analysis complete");
                    // Mark threat as analyzed in global queue
                    std::lock_guard<std::mutex> lk(g_hunt_mutex);
                    if (row < static_cast<int>(g_hunt_queue.size())) {
                        // find matching entry by name+source
                        for (auto& qt : g_hunt_queue) {
                            if (qt.name == state->threats[row].name &&
                                qt.source == state->threats[row].source) {
                                qt.analyzed = true;
                                qt.ai_verdict = aiText->toPlainText().toStdString();
                                break;
                            }
                        }
                    }
                }
            });
        });
    };

    // Row selection
    QObject::connect(table, &QTableWidget::currentCellChanged,
                     page, [=](int row, int, int, int) {
        state->selectedRow = row;
        if (row < 0 || row >= static_cast<int>(state->threats.size())) return;

        // Enable action buttons
        analyzeBtn->setEnabled(true);
        killBtn->setEnabled(true);
        quarBtn->setEnabled(true);
        whiteBtn->setEnabled(true);

        const auto& t = state->threats[row];
        threatStrip->setVisible(true);
        stripName->setText(QString::fromStdString(t.name));
        stripRisk->setText(QString("%1 (%2)").arg(
            QString::fromStdString(riskLabel(t.risk_score).toStdString()))
                               .arg(t.risk_score));
        stripRisk->setStyleSheet(QString("font-size:11px;font-weight:700;padding:2px 8px;"
                                         "border-radius:4px;border:1px solid %1;color:%1;")
                                     .arg(riskColor(t.risk_score)));
        stripPath->setText(QString::fromStdString(t.path));

        if (t.analyzed && !t.ai_verdict.empty()) {
            aiText->setPlainText(QString::fromStdString(t.ai_verdict));
            aiStatus->setText("Cached analysis");
        } else {
            aiText->clear();
            aiStatus->setText("Not yet analyzed");
        }
    });

    // Analyze button
    QObject::connect(analyzeBtn, &QPushButton::clicked, page, [=]() {
        doAnalyze(state->selectedRow);
    });

    // Hunt All: analyze every unanalyzed threat sequentially
    QObject::connect(huntBtn, &QPushButton::clicked, page, [=]() {
        if (state->aiRunning || !ai) return;
        for (int i = 0; i < static_cast<int>(state->threats.size()); ++i) {
            if (!state->threats[i].analyzed) {
                table->selectRow(i);
                doAnalyze(i);
                return; // analyze one at a time; timer will pick up the next
            }
        }
    });

    // Kill process button
    QObject::connect(killBtn, &QPushButton::clicked, page, [=]() {
        int row = state->selectedRow;
        if (row < 0 || row >= static_cast<int>(state->threats.size())) return;
        const auto& t = state->threats[row];
        // Find PID by path
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                                        FALSE, pe.th32ProcessID);
                if (ph) {
                    wchar_t buf[MAX_PATH]{};
                    DWORD sz = MAX_PATH;
                    if (QueryFullProcessImageNameW(ph, 0, buf, &sz)) {
                        std::wstring ws(buf, sz);
                        std::wstring target(t.path.begin(), t.path.end());
                        if (ws == target) {
                            TerminateProcess(ph, 1);
                            CloseHandle(ph);
                            CloseHandle(snap);
                            QMessageBox::information(page, "Hunt Complete",
                                QString("Process terminated: %1")
                                    .arg(QString::fromStdString(t.name)));
                            return;
                        }
                    }
                    CloseHandle(ph);
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        QMessageBox::warning(page, "Hunt", "Process not found or already terminated.");
    });

    // Quarantine button
    QObject::connect(quarBtn, &QPushButton::clicked, page, [=]() {
        int row = state->selectedRow;
        if (row < 0 || row >= static_cast<int>(state->threats.size())) return;
        const auto& t = state->threats[row];
        std::wstring src(t.path.begin(), t.path.end());
        std::wstring dst = L"C:\\ProgramData\\TeoAVSuite\\Quarantine\\" +
                           std::wstring(t.name.begin(), t.name.end()) + L".quarantine";
        CreateDirectoryW(L"C:\\ProgramData\\TeoAVSuite\\Quarantine", nullptr);
        if (MoveFileExW(src.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            QMessageBox::information(page, "Quarantined",
                QString("Moved to quarantine: %1").arg(QString::fromStdString(t.name)));
        } else {
            QMessageBox::warning(page, "Quarantine Failed",
                QString("Could not move file (error %1). May need elevation.")
                    .arg(GetLastError()));
        }
    });

    // Whitelist button
    QObject::connect(whiteBtn, &QPushButton::clicked, page, [=]() {
        int row = state->selectedRow;
        if (row < 0 || row >= static_cast<int>(state->threats.size())) return;
        {
            std::lock_guard<std::mutex> lk(g_hunt_mutex);
            auto it = g_hunt_queue.begin();
            std::advance(it, std::min(static_cast<size_t>(row), g_hunt_queue.size()));
            if (it != g_hunt_queue.end()) g_hunt_queue.erase(it);
        }
        refreshTable();
        aiText->clear();
        threatStrip->setVisible(false);
        aiStatus->setText("Threat removed");
    });

    // Clear button
    QObject::connect(clearBtn, &QPushButton::clicked, page, [=]() {
        std::lock_guard<std::mutex> lk(g_hunt_mutex);
        g_hunt_queue.clear();
    });

    // Auto-toggle
    QObject::connect(autoToggle, &QCheckBox::toggled, page, [=](bool checked) {
        state->autoAnalyze = checked;
    });

    // ── Periodic refresh timer ───────────────────────────────────────────────
    auto* refreshTimer = new QTimer(page);
    refreshTimer->setInterval(1500);
    QObject::connect(refreshTimer, &QTimer::timeout, page, [=]() {
        bool hasNew = g_hunt_new_item.exchange(false);
        if (hasNew) {
            refreshTable();
            // Auto-analyze first unanalyzed threat if enabled
            if (state->autoAnalyze && !state->aiRunning && ai) {
                for (int i = 0; i < static_cast<int>(state->threats.size()); ++i) {
                    if (!state->threats[i].analyzed) {
                        table->selectRow(i);
                        doAnalyze(i);
                        break;
                    }
                }
            }
        }
    });
    refreshTimer->start();

    // Initial load
    refreshTable();

    // Cleanup
    QObject::connect(page, &QWidget::destroyed, page, [=]() {
        refreshTimer->stop();
        delete state;
    });

    return page;
}

} // namespace avdashboard
