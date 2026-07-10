// main_window_threatintel.cpp — Threat Intel feed.
//
// Pulls abuse.ch MalwareBazaar's public "recent additions" CSV feed (SHA-256
// hashes of malware samples seen in the wild recently, with a family/
// signature name) and merges any hashes not already present into the local
// hash blacklist, so future scans flag them immediately without needing a
// full signature-DB update.
//
// Scope note: this page only pulls external IOC data into the local
// blacklist. It deliberately does NOT implement "self-upgrading AV" (auto
// downloading and replacing the app's own binaries) — that needs a signed-
// release + verification design of its own and shouldn't be bolted on here.
//
// ASCII labels (MSVC builds without /utf-8).

#include "main_window.hpp"
#include "av_quit_guard.hpp"
#include "theme.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
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

QWidget* BuildThreatIntelPage(QWidget* parent) {
    auto* win = qobject_cast<MainWindow*>(parent);
    auto* page = new QWidget();
    page->setStyleSheet(QString("background:%1;").arg(theme::Bg));
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(theme::Space6, theme::Space6, theme::Space6, theme::Space6);
    root->setSpacing(theme::Space3);

    auto* update_btn = new QPushButton(QString::fromUtf8("Update from MalwareBazaar"), page);
    update_btn->setObjectName("PrimaryBtn");
    update_btn->setCursor(Qt::PointingHandCursor);

    root->addWidget(theme::BuildPageHeader(
        "Threat Intel",
        "Pulls the abuse.ch MalwareBazaar recent-additions feed and merges new SHA-256 "
        "hashes into the local blacklist, so scans flag them immediately. Needs a free "
        "Auth-Key from bazaar.abuse.ch (Settings -> Security).",
        update_btn));

    auto* status = new QLabel(QString::fromUtf8("Idle. Click Update to pull the latest feed."), page);
    status->setStyleSheet(QString("color:%1; font-size:%2px; background:transparent;")
                              .arg(theme::Muted).arg(theme::FontBody));
    root->addWidget(status);

    auto* table = new QTableWidget(0, 2, page);
    table->setHorizontalHeaderLabels({"SHA-256", "Signature"});
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
        " padding:8px 10px; border:none; border-bottom:1px solid %4; }")
        .arg(theme::Surface).arg(theme::Text).arg(theme::FontBody).arg(theme::Border)
        .arg(theme::RadiusLg).arg(theme::Surface2).arg(theme::Sidebar).arg(theme::Dim)
        .arg(theme::FontCaption));
    {
        auto* h = table->horizontalHeader();
        h->setStretchLastSection(true);
        h->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    }
    root->addWidget(table, 1);

    ArmQuitGuard(page);
    auto fetching = std::make_shared<std::atomic<bool>>(false);

    QObject::connect(update_btn, &QPushButton::clicked, page,
            [update_btn, status, table, fetching, win]() {
        if (!win || fetching->load()) return;
        fetching->store(true);
        update_btn->setEnabled(false);
        table->setRowCount(0);
        status->setText(QString::fromUtf8("Fetching feed from bazaar.abuse.ch..."));

        std::thread([status, table, fetching, win]() {
            const auto result = win->FetchThreatIntelFeed();
            if (AppQuitting().load()) return;

            QMetaObject::invokeMethod(status, [status, table, fetching, win, result]() {
                fetching->store(false);
                if (!result.success) {
                    status->setText(QString::fromUtf8("Error: ") + QString::fromStdString(result.error));
                    return;
                }
                const int added = win->ImportThreatIntelHashes(result.entries);
                for (const auto& [sha256, note] : result.entries) {
                    const int row = table->rowCount();
                    table->insertRow(row);
                    table->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(sha256)));
                    table->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(note)));
                }
                status->setText(QString::fromUtf8("Fetched %1 hashes from feed, %2 new -> added to blacklist.")
                    .arg(static_cast<int>(result.entries.size())).arg(added));
            }, Qt::QueuedConnection);
        }).detach();
    });

    auto* sync = new QTimer(page);
    sync->setInterval(300);
    QObject::connect(sync, &QTimer::timeout, update_btn, [update_btn, fetching]() {
        update_btn->setEnabled(!fetching->load());
    });
    sync->start();

    return page;
}

} // namespace avdashboard
