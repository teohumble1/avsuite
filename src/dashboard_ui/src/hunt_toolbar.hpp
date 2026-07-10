// hunt_toolbar.hpp — shared Clean/Export controls for the hunt-style pages.
//
// Every hunt page (Memory, Hidden, Hook, Supply-chain, SysWatch, DLL Intel,
// LAN Monitor) shows results in a QTableWidget. Clean (clear the table) and
// Export (dump the table to CSV) are identical across all of them, so they
// live here instead of being copy-pasted six times. Stop stays per-page
// because each page signals cancellation differently (some flip the same
// `scanning` flag the worker polls, some use a dedicated `cancel` atomic).

#pragma once

#include <QFile>
#include <QFileDialog>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QWidget>

#include "theme.hpp"

namespace avdashboard {

// Creates a "Clean" button that clears `table`. Returns it so the caller can
// manage its enabled state (e.g. disable while a scan is running).
inline QPushButton* MakeCleanButton(QWidget* page, QTableWidget* table,
                                    QLabel* status = nullptr) {
    auto* btn = new QPushButton(QString::fromUtf8("Clean"), page);
    btn->setCursor(Qt::PointingHandCursor);
    btn->setEnabled(false);
    btn->setStyleSheet(QString(
        "QPushButton { background:transparent; border:1px solid %1; border-radius:%2px;"
        " color:%3; font-size:%4px; font-weight:600; padding:9px 18px; }"
        "QPushButton:hover { border-color:%5; color:%5; }"
        "QPushButton:disabled { background:%6; color:%7; border-color:%1; }")
        .arg(theme::Border).arg(theme::RadiusMd).arg(theme::Text).arg(theme::FontBody)
        .arg(theme::Accent).arg(theme::Surface).arg(theme::Dim));
    QObject::connect(btn, &QPushButton::clicked, page, [table, status] {
        table->setRowCount(0);
        if (status) status->setText(QString::fromUtf8("Idle."));
    });
    return btn;
}

// Creates an "Export" button that writes the whole table to a CSV file chosen
// via a save dialog. Returns it so the caller can manage enabled state.
inline QPushButton* MakeExportButton(QWidget* page, QTableWidget* table,
                                     const QString& default_name,
                                     QLabel* status = nullptr) {
    auto* btn = new QPushButton(QString::fromUtf8("Export"), page);
    btn->setCursor(Qt::PointingHandCursor);
    btn->setEnabled(false);
    btn->setStyleSheet(QString(
        "QPushButton { background:transparent; border:1px solid %1; border-radius:%2px;"
        " color:%1; font-size:%3px; font-weight:600; padding:9px 18px; }"
        "QPushButton:hover { background:rgba(74,222,128,0.12); }"
        "QPushButton:disabled { background:%4; color:%5; border-color:%6; }")
        .arg(theme::Safe).arg(theme::RadiusMd).arg(theme::FontBody)
        .arg(theme::Surface).arg(theme::Dim).arg(theme::Border));
    QObject::connect(btn, &QPushButton::clicked, page, [page, table, default_name, status] {
        if (table->rowCount() == 0) return;
        const QString fn = QFileDialog::getSaveFileName(
            page, QString::fromUtf8("Export findings"), default_name,
            QString::fromUtf8("CSV files (*.csv);;All files (*.*)"));
        if (fn.isEmpty()) return;
        QFile out(fn);
        if (!out.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(page, QString::fromUtf8("Export failed"),
                QString::fromUtf8("Could not open the file for writing."));
            return;
        }
        QTextStream ts(&out);
        const int cols = table->columnCount();
        QStringList headers;
        for (int c = 0; c < cols; ++c) {
            auto* hi = table->horizontalHeaderItem(c);
            headers << (hi ? hi->text() : QString());
        }
        ts << headers.join(',') << '\n';
        auto esc = [](QString v) -> QString {
            if (v.contains(',') || v.contains('"') || v.contains('\n')) {
                v.replace('"', "\"\"");
                return '"' + v + '"';
            }
            return v;
        };
        for (int r = 0; r < table->rowCount(); ++r) {
            QStringList row;
            for (int c = 0; c < cols; ++c) {
                const auto* it = table->item(r, c);
                row << esc(it ? it->text() : QString());
            }
            ts << row.join(',') << '\n';
        }
        out.close();
        if (status)
            status->setText(QString::fromUtf8("Exported %1 finding(s) to %2")
                                .arg(table->rowCount()).arg(fn));
    });
    return btn;
}

} // namespace avdashboard
