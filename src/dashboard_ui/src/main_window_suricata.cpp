// main_window_suricata.cpp — Suricata IDS/IPS integration (#5 in the backlog).
//
// Deliberately does NOT bundle or auto-download a suricata.exe binary --
// pulling in a third-party network-capture executable without review is a
// supply-chain risk. Instead: detect an already-installed Suricata (common
// install paths + PATH), let the user pick an interface (via Suricata's own
// --list-interfaces, so numbering always matches what Suricata expects) and
// a config file, launch it as a child process, and tail its eve.json alert
// log into an Alerts table. If Suricata isn't installed, the page says so
// and links nowhere -- no auto-install. ASCII labels only (MSVC builds
// without /utf-8 for narrow string literals elsewhere in this codebase).

#include "main_window.hpp"
#include "theme.hpp"

#include <QAbstractItemView>
#include <QComboBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QStandardPaths>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "av_quit_guard.hpp"

namespace avdashboard {
namespace {

struct SuricataInstall {
    bool    found = false;
    QString exe_path;
};

SuricataInstall DetectSuricata() {
    SuricataInstall r;
    const QStringList candidates{
        "C:/Program Files/Suricata/suricata.exe",
        "C:/Program Files (x86)/Suricata/suricata.exe",
    };
    for (const auto& c : candidates) {
        if (QFileInfo::exists(c)) { r.found = true; r.exe_path = c; return r; }
    }
    const QString on_path = QStandardPaths::findExecutable("suricata");
    if (!on_path.isEmpty()) { r.found = true; r.exe_path = on_path; return r; }
    return r;
}

QString DefaultConfigFor(const QString& exe_path) {
    const QFileInfo fi(exe_path);
    return fi.absolutePath() + "/suricata.yaml";
}

struct SuricataAlert {
    QString time;
    QString severity;   // 1/2/3 -> High/Medium/Low
    QString signature;
    QString src;
    QString dst;
    QString category;
};

QString SeverityLabel(int sev) {
    if (sev <= 1) return "High";
    if (sev == 2) return "Medium";
    return "Low";
}

QColor SeverityColor(const QString& label) {
    if (label == "High")   return QColor(0xFF, 0x5A, 0x6A);
    if (label == "Medium") return QColor(0xFF, 0x7A, 0x00);
    return QColor(0x8B, 0x8B, 0x8B);
}

} // namespace

QWidget* BuildSuricataPage(QWidget* parent) {
    auto* page = new QWidget(parent);
    page->setStyleSheet("background:#120B06;");
    ArmQuitGuard(page);
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(20, 18, 20, 18);
    root->setSpacing(12);

    auto* title = new QLabel(QString::fromUtf8("Suricata IDS/IPS"), page);
    title->setStyleSheet("color:#E8E8E8; font-size:18px; font-weight:700; background:transparent;");
    root->addWidget(title);

    auto* subtitle = new QLabel(QString::fromUtf8(
        "Tich hop voi Suricata da cai san tren may (khong tu dong tai/bundle binary). "
        "Neu chua co Suricata, cai tu suricata.io roi bam 'Kiem tra lai'."), page);
    subtitle->setWordWrap(true);
    subtitle->setStyleSheet("color:#8B8B8B; font-size:11.5px; background:transparent;");
    root->addWidget(subtitle);

    // ── Status card ──────────────────────────────────────────────────────────
    auto* status_card = new QWidget(page);
    status_card->setStyleSheet("background:#1C1008; border:1px solid #2A1F14; border-radius:10px;");
    auto* sc_l = new QVBoxLayout(status_card);
    sc_l->setContentsMargins(14, 12, 14, 12);
    sc_l->setSpacing(8);

    auto* status_row = new QHBoxLayout();
    auto* status_lbl = new QLabel(QString::fromUtf8("Dang kiem tra..."), status_card);
    status_lbl->setStyleSheet("color:#E8E8E8; font-size:13px; background:transparent;");
    auto* recheck_btn = new QPushButton(QString::fromUtf8("Kiem tra lai"), status_card);
    recheck_btn->setFixedHeight(28);
    recheck_btn->setStyleSheet(
        "QPushButton { background:#1C1008; border:1px solid #FF7A00; border-radius:6px; "
        "              color:#FF9030; font-size:12px; padding:0 12px; }"
        "QPushButton:hover { background:#FF7A0030; }");
    status_row->addWidget(status_lbl, 1);
    status_row->addWidget(recheck_btn);
    sc_l->addLayout(status_row);

    // Config + interface row
    auto* cfg_row = new QHBoxLayout();
    auto* cfg_edit = new QLineEdit(status_card);
    cfg_edit->setPlaceholderText(QString::fromUtf8("Duong dan suricata.yaml"));
    cfg_edit->setStyleSheet(
        "QLineEdit { background:#130D07; border:1px solid #2A1F14; border-radius:6px; "
        "            color:#E8E8E8; padding:5px 8px; font-size:12px; }");
    auto* cfg_browse = new QPushButton("...", status_card);
    cfg_browse->setFixedSize(30, 28);
    cfg_browse->setStyleSheet(
        "QPushButton { background:#1C1008; border:1px solid #2A1F14; border-radius:6px; color:#ccc; }"
        "QPushButton:hover { background:#2A1F14; }");
    auto* iface_combo = new QComboBox(status_card);
    iface_combo->setMinimumWidth(220);
    iface_combo->setStyleSheet(
        "QComboBox { background:#130D07; border:1px solid #2A1F14; border-radius:6px; "
        "            color:#E8E8E8; padding:5px 8px; font-size:12px; }");
    auto* list_ifaces_btn = new QPushButton(QString::fromUtf8("Lay danh sach interface"), status_card);
    list_ifaces_btn->setFixedHeight(28);
    list_ifaces_btn->setStyleSheet(
        "QPushButton { background:#1C1008; border:1px solid #2A1F14; border-radius:6px; "
        "              color:#ccc; font-size:12px; padding:0 10px; }"
        "QPushButton:hover { background:#2A1F14; }");
    cfg_row->addWidget(new QLabel(QString::fromUtf8("Config:"), status_card));
    cfg_row->addWidget(cfg_edit, 1);
    cfg_row->addWidget(cfg_browse);
    sc_l->addLayout(cfg_row);

    auto* iface_row = new QHBoxLayout();
    iface_row->addWidget(new QLabel(QString::fromUtf8("Interface:"), status_card));
    iface_row->addWidget(iface_combo, 1);
    iface_row->addWidget(list_ifaces_btn);
    sc_l->addLayout(iface_row);

    auto* action_row = new QHBoxLayout();
    auto* start_btn = new QPushButton(QString::fromUtf8("Bat dau giam sat"), status_card);
    start_btn->setFixedHeight(30);
    start_btn->setStyleSheet(
        "QPushButton { background:#1C2226; border:1px solid #4ADE80; border-radius:6px; "
        "              color:#4ADE80; font-size:12px; padding:0 14px; }"
        "QPushButton:hover { background:#4ADE8030; }"
        "QPushButton:disabled { background:#1C1008; border-color:#333; color:#555; }");
    auto* stop_btn = new QPushButton(QString::fromUtf8("Dung"), status_card);
    stop_btn->setFixedHeight(30);
    stop_btn->setEnabled(false);
    stop_btn->setStyleSheet(
        "QPushButton { background:#1C2226; border:1px solid #FF5A6A; border-radius:6px; "
        "              color:#FF5A6A; font-size:12px; padding:0 14px; }"
        "QPushButton:hover { background:#FF5A6A30; }"
        "QPushButton:disabled { background:#1C1008; border-color:#333; color:#555; }");
    auto* running_lbl = new QLabel(QString::fromUtf8(""), status_card);
    running_lbl->setStyleSheet("color:#8B8B8B; font-size:11.5px; background:transparent;");
    action_row->addWidget(start_btn);
    action_row->addWidget(stop_btn);
    action_row->addWidget(running_lbl, 1);
    sc_l->addLayout(action_row);

    root->addWidget(status_card);

    // ── Alerts table ─────────────────────────────────────────────────────────
    auto* tbl = new QTableWidget(0, 6, page);
    tbl->setHorizontalHeaderLabels({
        "Time", "Severity", "Signature", "Source", "Dest", "Category"
    });
    tbl->horizontalHeader()->setStretchLastSection(false);
    tbl->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    tbl->setColumnWidth(0, 90);
    tbl->setColumnWidth(1, 70);
    tbl->setColumnWidth(3, 150);
    tbl->setColumnWidth(4, 150);
    tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tbl->setShowGrid(false);
    tbl->verticalHeader()->hide();
    tbl->setStyleSheet(
        theme::TableQss());
    root->addWidget(tbl, 1);

    // ── Shared state ─────────────────────────────────────────────────────────
    struct SuricataState {
        std::unique_ptr<QProcess> proc;
        std::atomic<bool> tailing{false};
        std::thread tail_thread;
        std::string log_dir;
    };
    auto ws = std::make_shared<SuricataState>();

    auto addAlertRow = [tbl](const SuricataAlert& a) {
        const int row = tbl->rowCount();
        tbl->insertRow(row);
        auto mk = [](const QString& s, QColor c = QColor(0xE8, 0xE8, 0xE8)) {
            auto* it = new QTableWidgetItem(s);
            it->setForeground(c);
            return it;
        };
        tbl->setItem(row, 0, mk(a.time, QColor(0x8B, 0x8B, 0x8B)));
        tbl->setItem(row, 1, mk(a.severity, SeverityColor(a.severity)));
        tbl->setItem(row, 2, mk(a.signature));
        tbl->setItem(row, 3, mk(a.src, QColor(0x8B, 0x8B, 0x8B)));
        tbl->setItem(row, 4, mk(a.dst, QColor(0x8B, 0x8B, 0x8B)));
        tbl->setItem(row, 5, mk(a.category, QColor(0x8B, 0x8B, 0x8B)));
        tbl->setRowHeight(row, 30);
        tbl->scrollToBottom();
    };

    // ── Detection / re-check ─────────────────────────────────────────────────
    auto runDetect = [=] {
        const auto info = DetectSuricata();
        if (info.found) {
            status_lbl->setText(QString::fromUtf8("Da tim thay Suricata: ") + info.exe_path);
            status_lbl->setStyleSheet("color:#4ADE80; font-size:13px; background:transparent;");
            if (cfg_edit->text().isEmpty()) cfg_edit->setText(DefaultConfigFor(info.exe_path));
            start_btn->setEnabled(true);
            list_ifaces_btn->setEnabled(true);
        } else {
            status_lbl->setText(QString::fromUtf8(
                "Khong tim thay Suricata (da kiem tra Program Files va PATH). "
                "Cai dat tu suricata.io neu muon dung tinh nang nay -- AvSuite khong tu tai binary."));
            status_lbl->setStyleSheet("color:#FF7A00; font-size:13px; background:transparent;");
            start_btn->setEnabled(false);
            list_ifaces_btn->setEnabled(false);
        }
    };
    QObject::connect(recheck_btn, &QPushButton::clicked, page, runDetect);

    QObject::connect(cfg_browse, &QPushButton::clicked, page, [=] {
        const QString f = QFileDialog::getOpenFileName(page, QString::fromUtf8("Chon suricata.yaml"),
            cfg_edit->text(), "YAML (*.yaml *.yml);;All files (*)");
        if (!f.isEmpty()) cfg_edit->setText(f);
    });

    // "--list-interfaces" is a quick, synchronous call -- same pattern as the
    // Firewall Pro page's blocking QProcess::execute("netsh", ...) on click.
    QObject::connect(list_ifaces_btn, &QPushButton::clicked, page, [=] {
        const auto info = DetectSuricata();
        if (!info.found) return;
        QProcess p;
        p.start(info.exe_path, {"--list-interfaces"});
        if (!p.waitForFinished(4000)) {
            p.kill();
            QMessageBox::warning(page, "Suricata", QString::fromUtf8("Timeout khi lay danh sach interface."));
            return;
        }
        const QString out = QString::fromUtf8(p.readAllStandardOutput());
        iface_combo->clear();
        // Suricata prints lines like "1) \Device\NPF_{GUID} (Description)"
        static const QRegularExpression re(R"(^\s*(\d+)\)\s*(.+)$)");
        for (const auto& line : out.split('\n')) {
            const auto m = re.match(line.trimmed());
            if (!m.hasMatch()) continue;
            iface_combo->addItem(m.captured(2).trimmed(), m.captured(1));
        }
        if (iface_combo->count() == 0) {
            QMessageBox::information(page, "Suricata", QString::fromUtf8(
                "Suricata khong tra ve interface nao. Can cai Npcap (khong phai WinPcap) de Suricata "
                "thay duoc card mang tren Windows."));
        }
    });

    // ── Tail eve.json on a background thread ────────────────────────────────
    auto startTail = [=](const std::string& log_dir) {
        ws->log_dir = log_dir;
        ws->tailing = true;
        ws->tail_thread = std::thread([ws, page, addAlertRow] {
            const std::string path = ws->log_dir + "\\eve.json";
            std::streamoff pos = 0;
            // Wait for the file to appear (Suricata creates it after init).
            for (int i = 0; i < 100 && ws->tailing; ++i) {
                std::ifstream probe(path);
                if (probe.good()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            while (ws->tailing) {
                std::ifstream f(path, std::ios::in);
                if (f.good()) {
                    f.seekg(0, std::ios::end);
                    const std::streamoff end = f.tellg();
                    if (end > pos) {
                        f.seekg(pos);
                        std::string line;
                        while (std::getline(f, line)) {
                            if (!line.empty()) {
                                try {
                                    auto j = nlohmann::json::parse(line);
                                    if (j.value("event_type", "") == "alert") {
                                        SuricataAlert a;
                                        a.time = QString::fromStdString(j.value("timestamp", ""));
                                        const int sev = j["alert"].value("severity", 3);
                                        a.severity  = SeverityLabel(sev);
                                        a.signature = QString::fromStdString(j["alert"].value("signature", ""));
                                        a.category  = QString::fromStdString(j["alert"].value("category", ""));
                                        const std::string sip = j.value("src_ip", "");
                                        const std::string dip = j.value("dest_ip", "");
                                        const int sport = j.value("src_port", 0);
                                        const int dport = j.value("dest_port", 0);
                                        a.src = QString::fromStdString(sip) +
                                                (sport ? (":" + QString::number(sport)) : "");
                                        a.dst = QString::fromStdString(dip) +
                                                (dport ? (":" + QString::number(dport)) : "");
                                        if (!AppQuitting().load()) {
                                            QMetaObject::invokeMethod(page, [addAlertRow, a] {
                                                addAlertRow(a);
                                            }, Qt::QueuedConnection);
                                        }
                                    }
                                } catch (...) {
                                    // partial/malformed line (e.g. Suricata still writing it) -- skip
                                }
                            }
                        }
                        pos = end;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
        });
    };
    auto stopTail = [=] {
        ws->tailing = false;
        if (ws->tail_thread.joinable()) ws->tail_thread.join();
    };

    QObject::connect(start_btn, &QPushButton::clicked, page, [=] {
        const auto info = DetectSuricata();
        if (!info.found) return;
        if (iface_combo->count() == 0) {
            QMessageBox::information(page, "Suricata", QString::fromUtf8(
                "Bam 'Lay danh sach interface' truoc va chon 1 interface."));
            return;
        }
        const QString cfg = cfg_edit->text();
        if (cfg.isEmpty() || !QFileInfo::exists(cfg)) {
            QMessageBox::warning(page, "Suricata", QString::fromUtf8(
                "Khong tim thay file config. Kiem tra duong dan suricata.yaml."));
            return;
        }
        const std::string log_dir = "C:\\ProgramData\\TeoAVSuite\\suricata_logs";
        CreateDirectoryW(L"C:\\ProgramData\\TeoAVSuite", nullptr);
        CreateDirectoryW(L"C:\\ProgramData\\TeoAVSuite\\suricata_logs", nullptr);

        ws->proc = std::make_unique<QProcess>(page);
        const QString iface_idx = iface_combo->currentData().toString();
        ws->proc->setProgram(info.exe_path);
        ws->proc->setArguments({
            "-c", cfg,
            "-i", iface_idx,
            "-l", QString::fromStdString(log_dir),
        });
        QProcess* proc_ptr = ws->proc.get();
        QObject::connect(proc_ptr, &QProcess::errorOccurred, page, [=](QProcess::ProcessError) {
            running_lbl->setText(QString::fromUtf8("Loi khoi chay Suricata: ") + proc_ptr->errorString());
        });
        QObject::connect(proc_ptr,
            static_cast<void(QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished),
            page, [=](int code, QProcess::ExitStatus) {
                running_lbl->setText(QString::fromUtf8("Suricata da dung (exit code %1).").arg(code));
                start_btn->setEnabled(true);
                stop_btn->setEnabled(false);
                stopTail();
            });

        ws->proc->start();
        if (!ws->proc->waitForStarted(4000)) {
            QMessageBox::warning(page, "Suricata", QString::fromUtf8(
                "Khong khoi chay duoc Suricata. Co the can chay AvSuite voi quyen Administrator."));
            ws->proc.reset();
            return;
        }
        running_lbl->setText(QString::fromUtf8("Dang giam sat interface \"") +
                              iface_combo->currentText() + "\"...");
        start_btn->setEnabled(false);
        stop_btn->setEnabled(true);
        startTail(log_dir);
    });

    QObject::connect(stop_btn, &QPushButton::clicked, page, [=] {
        if (ws->proc) {
            ws->proc->terminate();
            if (!ws->proc->waitForFinished(3000)) ws->proc->kill();
        }
        stopTail();
        start_btn->setEnabled(true);
        stop_btn->setEnabled(false);
        running_lbl->setText(QString::fromUtf8("Da dung."));
    });

    QObject::connect(page, &QObject::destroyed, page, [ws] {
        ws->tailing = false;
        if (ws->tail_thread.joinable()) ws->tail_thread.join();
        if (ws->proc && ws->proc->state() != QProcess::NotRunning) {
            ws->proc->terminate();
            ws->proc->waitForFinished(2000);
        }
    });

    runDetect();
    return page;
}

} // namespace avdashboard
