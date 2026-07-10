// main_window_alerts.cpp — Real-time threat alerts.
// Shows notable (Suspicious+) detections pulled live from the engine, styled on
// the shared design tokens in theme.hpp. Clear dismisses from view (does not
// touch the database); Export writes the current view to CSV.

#include <QAbstractItemView>
#include <QColor>
#include <QDateTime>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <chrono>

#include "avcore/severity.hpp"
#include "main_window.hpp"
#include "theme.hpp"

namespace avdashboard {

namespace {

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

} // namespace

QWidget* BuildAlertsPage(QWidget* parent) {
    auto* win = qobject_cast<MainWindow*>(parent);

    auto* page = new QWidget();
    page->setStyleSheet(QString("background:%1;").arg(theme::Bg));
    auto* layout = new QVBoxLayout(page);
    layout->setSpacing(theme::Space3);
    layout->setContentsMargins(theme::Space6, theme::Space6, theme::Space6, theme::Space6);

    // Header with actions in the right-aligned slot.
    auto* actions = new QWidget();
    auto* actionRow = new QHBoxLayout(actions);
    actionRow->setContentsMargins(0, 0, 0, 0);
    actionRow->setSpacing(theme::Space2);
    auto* clearBtn = new QPushButton("Clear");
    clearBtn->setObjectName("GhostBtn");
    clearBtn->setCursor(Qt::PointingHandCursor);
    auto* exportBtn = new QPushButton("Export");
    exportBtn->setObjectName("GhostBtn");
    exportBtn->setCursor(Qt::PointingHandCursor);
    actionRow->addWidget(clearBtn);
    actionRow->addWidget(exportBtn);
    layout->addWidget(theme::BuildPageHeader(
        "Threat Alerts", "Notable detections from all scans, most recent first", actions));

    // Table + empty-state, swapped in a stack.
    auto* stack = new QStackedWidget();

    auto* table = new QTableWidget(0, 5, page);
    table->setHorizontalHeaderLabels({"Time", "Severity", "Rule", "Source", "Details"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setStyleSheet(QString(
        "QTableWidget { background:%1; color:%2; font-size:%3px; border:1px solid %4;"
        " border-radius:%5px; }"
        "QTableWidget::item { padding:8px 10px; border-bottom:1px solid %4; }"
        "QTableWidget::item:selected { background:%6; color:%2; }"
        "QHeaderView::section { background:%7; color:%8; font-size:%9px; font-weight:600;"
        " padding:8px 10px; border:none; border-bottom:1px solid %4; text-transform:uppercase; }")
        .arg(theme::Surface).arg(theme::Text).arg(theme::FontBody).arg(theme::Border)
        .arg(theme::RadiusLg).arg(theme::Surface2).arg(theme::Sidebar).arg(theme::Dim)
        .arg(theme::FontCaption));
    table->horizontalHeader()->setStretchLastSection(true);
    table->setColumnWidth(0, 150);
    table->setColumnWidth(1, 110);
    table->setColumnWidth(2, 190);
    table->setColumnWidth(3, 120);

    auto* empty = new QLabel("No active alerts — you're clear.");
    empty->setAlignment(Qt::AlignCenter);
    empty->setStyleSheet(QString(
        "color:%1; font-size:%2px; background:%3; border:1px solid %4; border-radius:%5px;")
        .arg(theme::Dim).arg(theme::FontSubhead).arg(theme::Surface)
        .arg(theme::Border).arg(theme::RadiusLg));

    stack->addWidget(table);  // index 0
    stack->addWidget(empty);  // index 1
    layout->addWidget(stack, 1);

    // Dismissal cutoff: Clear hides everything at/older than the newest currently
    // shown alert; genuinely newer detections still surface on the next refresh.
    auto dismissedBefore = std::make_shared<QDateTime>();

    auto populate = [win, table, stack, dismissedBefore]() {
        table->setRowCount(0);
        if (!win) { stack->setCurrentIndex(1); return; }

        const auto detections = win->GetRecentDetections(500);
        int shown = 0;
        for (const auto& d : detections) {
            if (d.severity == avcore::Severity::Info) continue;  // alerts = suspicious+
            const QDateTime when = ToQDateTime(d.timestamp);
            if (dismissedBefore->isValid() && when <= *dismissedBefore) continue;

            const int row = table->rowCount();
            table->insertRow(row);
            const char* sevColor = theme::SeverityColor(SeverityLabel(d.severity));

            auto* tItem   = new QTableWidgetItem(when.toString("yyyy-MM-dd HH:mm:ss"));
            auto* sItem   = new QTableWidgetItem(SeverityLabel(d.severity));
            auto* rItem   = new QTableWidgetItem(QString::fromStdString(d.rule_id));
            auto* srcItem = new QTableWidgetItem(QString::fromStdString(d.source));
            QString detail = QString::fromStdString(d.evidence.empty() ? d.target_path : d.evidence);
            auto* dItem   = new QTableWidgetItem(detail);

            sItem->setForeground(QColor(sevColor));
            tItem->setForeground(QColor(theme::Muted));
            rItem->setForeground(QColor(theme::Muted));
            srcItem->setForeground(QColor(theme::Muted));

            table->setItem(row, 0, tItem);
            table->setItem(row, 1, sItem);
            table->setItem(row, 2, rItem);
            table->setItem(row, 3, srcItem);
            table->setItem(row, 4, dItem);
            ++shown;
        }
        stack->setCurrentIndex(shown > 0 ? 0 : 1);
    };

    QObject::connect(clearBtn, &QPushButton::clicked, [populate, dismissedBefore]() {
        *dismissedBefore = QDateTime::currentDateTime();
        populate();
    });

    QObject::connect(exportBtn, &QPushButton::clicked, [table, page]() {
        const QString path = QFileDialog::getSaveFileName(
            page, "Export alerts", "avsuite-alerts.csv", "CSV (*.csv)");
        if (path.isEmpty()) return;
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) return;
        QTextStream out(&f);
        out << "Time,Severity,Rule,Source,Details\n";
        for (int r = 0; r < table->rowCount(); ++r) {
            QStringList cols;
            for (int c = 0; c < table->columnCount(); ++c) {
                QString v = table->item(r, c) ? table->item(r, c)->text() : QString();
                v.replace('"', "\"\"");
                cols << '"' + v + '"';
            }
            out << cols.join(',') << '\n';
        }
    });

    populate();
    auto* timer = new QTimer(page);
    QObject::connect(timer, &QTimer::timeout, page, [populate]() { populate(); });
    timer->start(4000);

    return page;
}

} // namespace avdashboard
