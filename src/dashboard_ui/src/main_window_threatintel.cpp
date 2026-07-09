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
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(12);

    auto* title = new QLabel(QString::fromUtf8("Threat Intel"), page);
    title->setStyleSheet("color:#E8E8E8; font-size:16pt; font-weight:800; background:transparent;");
    root->addWidget(title);
    auto* sub = new QLabel(QString::fromUtf8(
        "Pulls the abuse.ch MalwareBazaar recent-additions feed (public malware-hash "
        "intel) and merges new SHA-256 hashes into the local blacklist, so scans flag "
        "them immediately. Needs a free Auth-Key from bazaar.abuse.ch (set in Settings "
        "-> Security)."), page);
    sub->setStyleSheet("color:#8B8B8B; font-size:9pt; background:transparent;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(12);
    auto* update_btn = new QPushButton(QString::fromUtf8("Update from MalwareBazaar"), page);
    update_btn->setCursor(Qt::PointingHandCursor);
    update_btn->setStyleSheet(
        "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #CC5500);"
        " border:none; border-radius:10px; color:#fff; font-size:10.5pt; font-weight:700; padding:10px 24px; }"
        "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9030,stop:1 #DD6600); }"
        "QPushButton:disabled { background:#2A1F14; color:#8B8B8B; }");
    ctl->addWidget(update_btn);
    auto* status = new QLabel(QString::fromUtf8("Idle. Click Update to pull the latest feed."), page);
    status->setStyleSheet("color:#C8B8A8; font-size:9.5pt; background:transparent;");
    ctl->addWidget(status, 1);
    root->addLayout(ctl);

    auto* table = new QTableWidget(0, 2, page);
    table->setHorizontalHeaderLabels({"SHA-256", "Signature"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);
    table->setStyleSheet(
        "QTableWidget { background:#1C1008; color:#E8E8E8; font-size:9.5pt; border:1px solid #2A1F14;"
        " border-radius:10px; gridline-color:#2A1F14; }"
        "QTableWidget::item { padding:5px 8px; }"
        "QHeaderView::section { background:#130D07; color:#8B8B8B; font-size:9pt; font-weight:700;"
        " padding:6px; border:none; border-bottom:1px solid #2A1F14; }");
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
