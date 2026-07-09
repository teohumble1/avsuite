// main_window_alerts.cpp — Real-time threat alerts & notifications
// Aggregates critical detections from all scans with timestamps

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QLabel>
#include <QPushButton>
#include <QHeaderView>
#include <QDateTime>

namespace avdashboard {

QWidget* BuildAlertsPage(QWidget* parent) {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setSpacing(12);
    layout->setContentsMargins(20, 20, 20, 20);

    // Title
    auto* title = new QLabel("Real-Time Threat Alerts");
    title->setStyleSheet("color:#FF7A00; font-size:14pt; font-weight:700;");
    layout->addWidget(title);

    // Subtitle
    auto* subtitle = new QLabel("Critical detections from all scans with timestamps");
    subtitle->setStyleSheet("color:#8B8B8B; font-size:10pt;");
    layout->addWidget(subtitle);

    // Alert count
    auto* count_label = new QLabel("Alerts: 0");
    count_label->setStyleSheet("color:#E8E8E8; font-size:10pt;");
    layout->addWidget(count_label);

    // Alerts table
    auto* table = new QTableWidget(0, 5, page);
    table->setHorizontalHeaderLabels({"Time", "Severity", "Type", "Source", "Details"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setAlternatingRowColors(true);
    table->setStyleSheet(
        "QTableWidget { background:#1C1008; color:#E8E8E8; font-size:9.5pt; border:1px solid #2A1F14;"
        " border-radius:10px; gridline-color:#2A1F14; }"
        "QTableWidget::item { padding:5px 8px; }"
        "QHeaderView::section { background:#130D07; color:#8B8B8B; font-size:9pt; font-weight:700;"
        " padding:6px; border:none; border-bottom:1px solid #2A1F14; }");
    table->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(table, 1);

    // Control buttons
    auto* btn_layout = new QHBoxLayout();
    auto* clear_btn = new QPushButton("Clear Alerts");
    auto* export_btn = new QPushButton("Export Log");
    clear_btn->setStyleSheet(
        "QPushButton { background:#2A1F14; border:1px solid #3A2F24; border-radius:6px; color:#8B8B8B;"
        " padding:8px 16px; font-size:10pt; }"
        "QPushButton:hover { background:#3A2F24; }");
    export_btn->setStyleSheet(clear_btn->styleSheet());
    btn_layout->addWidget(clear_btn);
    btn_layout->addWidget(export_btn);
    btn_layout->addStretch();
    layout->addLayout(btn_layout);

    // Mock data (in real usage, these would be collected from scan results)
    auto add_alert = [table, count_label](const QString& time, const QString& severity,
                                           const QString& type, const QString& source,
                                           const QString& details) {
        const int row = table->rowCount();
        table->insertRow(row);

        // Color code by severity
        QString bg;
        if (severity == "CRITICAL") bg = "#3A1F1F";
        else if (severity == "HIGH") bg = "#3A2F1F";
        else if (severity == "MEDIUM") bg = "#2F3A1F";
        else bg = "#1F2F1F";

        auto* t = new QTableWidgetItem(time);
        auto* s = new QTableWidgetItem(severity);
        auto* ty = new QTableWidgetItem(type);
        auto* src = new QTableWidgetItem(source);
        auto* det = new QTableWidgetItem(details);

        for (auto* item : {t, s, ty, src, det}) {
            item->setBackground(QColor(bg));
        }

        table->setItem(row, 0, t);
        table->setItem(row, 1, s);
        table->setItem(row, 2, ty);
        table->setItem(row, 3, src);
        table->setItem(row, 4, det);

        count_label->setText(QString("Alerts: %1").arg(table->rowCount()));
    };

    // Example alerts (would be populated from actual scan results)
    add_alert(QDateTime::currentDateTime().toString("HH:mm:ss"), "CRITICAL",
              "Process Injection", "Memory Hunt", "Unbacked RWX region detected in explorer.exe");
    add_alert(QDateTime::currentDateTime().toString("HH:mm:ss"), "HIGH",
              "Hook Detected", "Hook Hunt", "AmsiScanBuffer patched - detour to unbacked memory");
    add_alert(QDateTime::currentDateTime().addSecs(-300).toString("HH:mm:ss"), "HIGH",
              "Credential Leak", "DLP", "AWS access key found in temp directory");

    // Clear button functionality
    QObject::connect(clear_btn, &QPushButton::clicked, [table, count_label]() {
        table->setRowCount(0);
        count_label->setText("Alerts: 0");
    });

    // Export button (placeholder)
    QObject::connect(export_btn, &QPushButton::clicked, [table]() {
        // In real implementation, export table to CSV/JSON
    });

    page->setStyleSheet("background:#120B06;");
    return page;
}

} // namespace avdashboard
