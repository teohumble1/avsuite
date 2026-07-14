#include "main_window.hpp"
#include "theme.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

#include <chrono>
#include <thread>

#include <QString>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QGroupBox>
#include <QTextEdit>
#include <QDateTime>
#include <QMetaObject>
#include <QPointer>

#include "avcore/severity.hpp"
#include "main_window.hpp"

namespace avdashboard {

namespace {

QString SeverityText(avcore::Severity s) {
    switch (s) {
        case avcore::Severity::Malicious:  return "Malicious";
        case avcore::Severity::Suspicious: return "Suspicious";
        default:                            return "Info";
    }
}

QColor SeverityColour(avcore::Severity s) {
    switch (s) {
        case avcore::Severity::Malicious:  return QColor(0xFF, 0x5A, 0x6A);
        case avcore::Severity::Suspicious: return QColor(0xFB, 0xBF, 0x24);
        default:                            return QColor(0x4A, 0xDE, 0x80);
    }
}

} // namespace

QWidget* BuildInvestigationPage(QWidget* parent) {
    auto page = new QWidget(parent);
    auto layout = new QVBoxLayout(page);

    // The page is built with the MainWindow as parent so it can pull real engine
    // data (detection history + VirusTotal lookups) through its public API.
    auto* mw = qobject_cast<MainWindow*>(parent);

    auto header = theme::BuildPageHeader("Investigation Console", "Deep file inspection & VirusTotal lookup");
    layout->addWidget(header);

    // ── File / hash VirusTotal lookup ────────────────────────────────────────
    auto fileGroupBox = new QGroupBox("File Hash Lookup", page);
    auto fileVLayout = new QVBoxLayout(fileGroupBox);
    auto fileLayout = new QHBoxLayout();

    auto hashInput = new QLineEdit(page);
    hashInput->setPlaceholderText("Enter SHA256, MD5, or SHA1...");
    fileLayout->addWidget(new QLabel("Hash:", page));
    fileLayout->addWidget(hashInput);

    auto vtLookupBtn = new QPushButton("Lookup on VirusTotal", page);
    fileLayout->addWidget(vtLookupBtn);
    fileVLayout->addLayout(fileLayout);

    auto vtResult = new QTextEdit(page);
    vtResult->setReadOnly(true);
    vtResult->setPlaceholderText("VirusTotal result appears here.");
    vtResult->setMaximumHeight(120);
    fileVLayout->addWidget(vtResult);
    layout->addWidget(fileGroupBox);

    // The VirusTotal call is a blocking network request, so run it on a worker
    // thread and post the result back to the GUI thread. QPointer guards against
    // the widgets being gone by the time the reply lands.
    QObject::connect(vtLookupBtn, &QPushButton::clicked, page, [mw, hashInput, vtResult, vtLookupBtn] {
        const QString hash = hashInput->text().trimmed();
        if (hash.isEmpty() || !mw) return;
        vtLookupBtn->setEnabled(false);
        vtResult->setPlainText("Đang tra VirusTotal...");
        QPointer<QTextEdit> resultPtr(vtResult);
        QPointer<QPushButton> btnPtr(vtLookupBtn);
        std::thread([mw, hash, resultPtr, btnPtr] {
            const QString reply = mw->LookupVtIoc("hash", hash);
            QMetaObject::invokeMethod(mw, [resultPtr, btnPtr, reply] {
                if (resultPtr) resultPtr->setPlainText(reply);
                if (btnPtr) btnPtr->setEnabled(true);
            });
        }).detach();
    });

    // ── Recent detections (real engine history) ──────────────────────────────
    auto tableGroupBox = new QGroupBox("Recent Detections (Last 100)", page);
    auto tableLayout = new QVBoxLayout(tableGroupBox);

    auto refreshBtn = new QPushButton("Refresh", page);
    tableLayout->addWidget(refreshBtn, 0, Qt::AlignLeft);

    auto detectionTable = new QTableWidget(page);
    detectionTable->setColumnCount(6);
    detectionTable->setHorizontalHeaderLabels({"Time", "Severity", "Rule", "Process", "File/Hash", "Details"});
    detectionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    detectionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    detectionTable->horizontalHeader()->setStretchLastSection(true);
    tableLayout->addWidget(detectionTable);
    layout->addWidget(tableGroupBox);

    auto reload = [mw, detectionTable] {
        detectionTable->setRowCount(0);
        if (!mw) return;
        const auto events = mw->GetRecentDetections(100);
        for (const auto& ev : events) {
            const int row = detectionTable->rowCount();
            detectionTable->insertRow(row);

            const auto tt = std::chrono::system_clock::to_time_t(ev.timestamp);
            detectionTable->setItem(row, 0, new QTableWidgetItem(
                QDateTime::fromSecsSinceEpoch(static_cast<qint64>(tt)).toString("yyyy-MM-dd HH:mm:ss")));

            auto* sevItem = new QTableWidgetItem(SeverityText(ev.severity));
            sevItem->setForeground(SeverityColour(ev.severity));
            detectionTable->setItem(row, 1, sevItem);

            detectionTable->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(ev.rule_id)));
            detectionTable->setItem(row, 3, new QTableWidgetItem(
                ev.process_id ? QString::number(ev.process_id) : QString("-")));
            detectionTable->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(ev.target_path)));
            detectionTable->setItem(row, 5, new QTableWidgetItem(QString::fromStdString(ev.evidence)));
        }
    };
    QObject::connect(refreshBtn, &QPushButton::clicked, page, reload);
    reload();  // initial fill with real data

    return page;
}

}  // namespace avdashboard
