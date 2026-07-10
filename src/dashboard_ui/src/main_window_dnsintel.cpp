// main_window_dnsintel.cpp — DNS & C2 Intel page.
//
// Two previously-orphaned modules made real and wired in here:
//   * DnsEtwMonitor -- live DNS query capture via the Microsoft-Windows-
//     DNS-Client ETW provider (event 3006), replacing what used to be a
//     sleep-loop that captured nothing.
//   * C2ThreatAnalyzer -- on-demand domain reputation lookup over a real
//     abuse.ch ThreatFox feed, replacing a hardcoded "fake IOC" list that
//     claimed to be real.
//
// Starting DNS monitoring needs Administrator (same constraint as the
// process ETW feed used elsewhere in this app) -- surfaced honestly via
// DnsEtwMonitor::SetErrorCallback rather than failing silently.
//
// ASCII labels (MSVC builds without /utf-8).

#include "main_window.hpp"
#include "theme.hpp"
#include "av_quit_guard.hpp"
#include "hunt_toolbar.hpp"
#include "dns_etw_monitor.hpp"
#include "c2_threat_analyzer.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QCoreApplication>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <atomic>
#include <memory>
#include <thread>

namespace avdashboard {
namespace {

QColor ThreatLevelColor(const QString& level) {
    if (level == "CRITICAL") return QColor(0xFF, 0x3B, 0x50);
    if (level == "HIGH") return QColor(0xFF, 0x7A, 0x00);
    if (level == "MEDIUM") return QColor(0xE6, 0xC2, 0x4A);
    return QColor(0x4A, 0xDE, 0x80); // SAFE
}

QColor VerdictColor(const QString& v) {
    if (v == "MALICIOUS") return QColor(0xFF, 0x3B, 0x50);
    if (v == "SUSPICIOUS") return QColor(0xE6, 0xC2, 0x4A);
    return QColor(0x8B, 0x73, 0x55); // UNKNOWN -- muted
}

} // namespace

QWidget* BuildDnsIntelPage(QWidget* parent) {
    (void)parent;
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(12);

    root->addWidget(theme::BuildPageHeader(
        "DNS & C2 Intel",
        "Live DNS query capture via ETW (Microsoft-Windows-DNS-Client), flagged against a real "
        "abuse.ch ThreatFox IOC feed -- not a simulated or hardcoded domain list. Starting live "
        "capture requires Administrator. Domain checks below are on-demand IOC lookups."));

    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(12);
    auto* start_btn = new QPushButton(QString::fromUtf8("Start monitoring"), page);
    start_btn->setCursor(Qt::PointingHandCursor);
    start_btn->setStyleSheet(
        "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #CC5500);"
        " border:none; border-radius:10px; color:#fff; font-size:10.5pt; font-weight:700; padding:10px 24px; }"
        "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9030,stop:1 #DD6600); }"
        "QPushButton:disabled { background:#3A2A1C; color:#8B7355; }");
    ctl->addWidget(start_btn);

    auto* status = new QLabel(QString::fromUtf8("Loading threat intel..."), page);
    status->setStyleSheet("color:#C7B6A2; font-size:9.5pt; background:transparent;");
    ctl->addWidget(status, 1);
    root->addLayout(ctl);

    auto* table = new QTableWidget(0, 4, page);
    table->setHorizontalHeaderLabels({"Time", "Domain", "Result IP", "Threat Level"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);
    table->setStyleSheet(theme::TableQss());
    {
        auto* h = table->horizontalHeader();
        h->setStretchLastSection(true);
        h->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(1, QHeaderView::Stretch);
        h->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    }
    root->addWidget(table, 1);

    auto* toolbar = new QHBoxLayout();
    auto* clean_btn = MakeCleanButton(page, table, status);
    auto* export_btn = MakeExportButton(page, table, QString::fromUtf8("dns_queries.csv"), status);
    toolbar->addWidget(clean_btn);
    toolbar->addWidget(export_btn);
    toolbar->addStretch();
    root->addLayout(toolbar);

    // ── Domain reputation check (on-demand IOC lookup) ──────────────────────
    auto* check_row = new QHBoxLayout();
    check_row->setSpacing(10);
    auto* domain_edit = new QLineEdit(page);
    domain_edit->setPlaceholderText(QString::fromUtf8("Check a domain against ThreatFox..."));
    domain_edit->setStyleSheet(
        "QLineEdit { background:#1C1008; color:#E8E8E8; border:1px solid rgba(255,122,0,40);"
        " border-radius:8px; padding:8px 10px; font-size:9.5pt; }");
    check_row->addWidget(domain_edit, 1);
    auto* check_btn = new QPushButton(QString::fromUtf8("Check reputation"), page);
    check_btn->setCursor(Qt::PointingHandCursor);
    check_btn->setStyleSheet(
        "QPushButton { background:#1C1008; border:1px solid rgba(255,122,0,40); border-radius:8px;"
        " color:#FF9030; font-size:9.5pt; padding:8px 16px; }"
        "QPushButton:hover { background:#2A1F14; }");
    check_row->addWidget(check_btn);
    root->addLayout(check_row);

    auto* check_result = new QLabel(QString::fromUtf8(""), page);
    check_result->setWordWrap(true);
    check_result->setStyleSheet("color:#C7B6A2; font-size:9.5pt; background:transparent;");
    root->addWidget(check_result);

    ArmQuitGuard(page);

    auto monitor = std::make_shared<DnsEtwMonitor>();
    auto analyzer = std::make_shared<C2ThreatAnalyzer>();

    // Load ThreatFox once up front, on a background thread, before the user
    // can meaningfully start monitoring or check a domain.
    std::thread([status, monitor, analyzer] {
        const bool dns_ok = monitor->FetchIocFeed();
        const bool c2_ok = analyzer->FetchRealIOC();
        if (AppQuitting().load()) return;
        QMetaObject::invokeMethod(status, [status, dns_ok, c2_ok] {
            if (dns_ok || c2_ok) {
                status->setText(QString::fromUtf8("Loaded threat intel from ThreatFox."));
            } else {
                status->setText(QString::fromUtf8(
                    "Could not reach ThreatFox (offline?) -- domain checks will show UNKNOWN until retried."));
            }
        }, Qt::QueuedConnection);
    }).detach();

    monitor->SetErrorCallback([status](const std::string& err) {
        QMetaObject::invokeMethod(status, [status, err] {
            status->setText(QString::fromUtf8("Could not start DNS monitoring: %1")
                                 .arg(QString::fromStdString(err)));
        }, Qt::QueuedConnection);
    });

    QObject::connect(start_btn, &QPushButton::clicked, page,
                     [start_btn, status, monitor]() mutable {
        if (monitor->IsMonitoring()) {
            monitor->StopMonitoring();
            start_btn->setText(QString::fromUtf8("Start monitoring"));
            status->setText(QString::fromUtf8("Stopped."));
        } else {
            monitor->StartMonitoring();
            start_btn->setText(QString::fromUtf8("Stop monitoring"));
            status->setText(QString::fromUtf8("Monitoring live DNS queries..."));
        }
    });

    QObject::connect(qApp, &QCoreApplication::aboutToQuit, page, [monitor] {
        monitor->StopMonitoring();
    });

    // Rebuild the table from the monitor's current buffer periodically --
    // same pattern main_window_c2monitor.cpp uses for its connection table.
    auto* poll = new QTimer(page);
    poll->setInterval(1500);
    QObject::connect(poll, &QTimer::timeout, page, [table, monitor] {
        if (!monitor->IsMonitoring()) return;
        const auto queries = monitor->GetRecentQueries(150);
        table->setRowCount(0);
        for (const auto& q : queries) {
            const int row = table->rowCount();
            table->insertRow(row);
            table->setItem(row, 0, new QTableWidgetItem(q.timestamp));
            table->setItem(row, 1, new QTableWidgetItem(q.domain));
            table->setItem(row, 2, new QTableWidgetItem(q.result_ip));
            auto* level = new QTableWidgetItem(q.threat_level);
            level->setForeground(ThreatLevelColor(q.threat_level));
            table->setItem(row, 3, level);
        }
    });
    poll->start();

    QObject::connect(check_btn, &QPushButton::clicked, page,
                     [domain_edit, check_result, analyzer]() {
        const QString domain = domain_edit->text().trimmed();
        if (domain.isEmpty()) return;
        const auto result = analyzer->AnalyzeDomain(domain);
        QString text = QString::fromUtf8("%1: verdict=%2")
                            .arg(domain, result.verdict);
        if (result.verdict != "UNKNOWN") {
            text += QString::fromUtf8(", family=%1, score=%2")
                        .arg(result.threat_family.isEmpty() ? QString::fromUtf8("(unknown)") : result.threat_family)
                        .arg(result.threat_score);
        } else {
            text += QString::fromUtf8(" (not found in the current ThreatFox feed -- not proof of safety)");
        }
        check_result->setText(text);
        check_result->setStyleSheet(QString(
            "font-size:9.5pt; background:transparent; color:%1;")
            .arg(VerdictColor(result.verdict).name()));
    });

    return page;
}

} // namespace avdashboard
