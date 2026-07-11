// main_window_hiddenhunt.cpp — Hunt for hidden / masqueraded malware.
//
// Scans a chosen folder recursively and flags files that try to disguise
// themselves as harmless data, or hide from the user:
//   * Double extension with an executable tail   (invoice.pdf.exe)
//   * Right-to-Left-Override / bidi trick in the name (spoofs the real ext)
//   * Content vs extension mismatch: a "data" file whose bytes are a PE (MZ)
//   * Hidden + System attributes on a normal user file
//   * Alternate Data Streams (a hidden payload attached to a visible file)
//
// All labels/messages are kept ASCII on purpose: this file is compiled by MSVC
// without /utf-8, so raw non-ASCII string literals would be mangled.

#include "main_window.hpp"
#include "av_quit_guard.hpp"
#include "hunt_toolbar.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QFile>
#include <QFileDialog>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <windows.h>
#include <ShlObj.h>
#pragma comment(lib, "shell32.lib")

#include <atomic>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace avdashboard {
namespace {

struct HiddenFinding {
    int         risk = 0;     // 0-100
    std::string type;         // short category
    std::string filename;
    std::string path;
    std::string detail;
};

std::string Utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), len, nullptr, nullptr);
    return s;
}

std::string LowerExt(const fs::path& p) {
    std::string e = p.extension().string();
    if (!e.empty() && e[0] == '.') e.erase(0, 1);
    for (auto& c : e) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return e;
}

bool InSet(const std::string& e, std::initializer_list<const char*> set) {
    for (const char* s : set) if (e == s) return true;
    return false;
}

bool IsExecExt(const std::string& e) {
    return InSet(e, {"exe","scr","com","pif","bat","cmd","vbs","vbe","js","jse",
                     "wsf","wsh","jar","ps1","msi","cpl","hta","lnk","dll"});
}

bool IsDataExt(const std::string& e) {
    return InSet(e, {"pdf","doc","docx","xls","xlsx","ppt","pptx","txt","rtf",
                     "jpg","jpeg","png","gif","bmp","webp","mp3","mp4","avi",
                     "mkv","zip","rar","7z","csv","html","htm"});
}

// Read up to n leading bytes; returns count actually read.
size_t ReadMagic(const fs::path& p, unsigned char* buf, size_t n) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return 0;
    f.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(n));
    return static_cast<size_t>(f.gcount());
}

// Unicode bidi/override controls used to reverse how a filename renders.
bool NameHasBidiOverride(const std::wstring& name) {
    for (wchar_t c : name) {
        if ((c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069)) return true;
    }
    return false;
}

// First named Alternate Data Stream (other than the default ::$DATA), or empty.
std::string FindExtraStream(const std::wstring& wpath) {
    WIN32_FIND_STREAM_DATA sd{};
    HANDLE h = FindFirstStreamW(wpath.c_str(), FindStreamInfoStandard, &sd, 0);
    if (h == INVALID_HANDLE_VALUE) return {};
    std::string result;
    do {
        const std::wstring sn = sd.cStreamName;
        if (sn != L"::$DATA") { result = Utf8(sn); break; }
    } while (FindNextStreamW(h, &sd));
    FindClose(h);
    return result;
}

void AnalyzeFile(const fs::path& p, std::vector<HiddenFinding>& out) {
    const std::wstring wpath = p.wstring();
    const std::string  fname = Utf8(p.filename().wstring());
    const std::string  spath = Utf8(wpath);
    const std::string  ext   = LowerExt(p);

    // 1) Bidi / RLO trick in the displayed name.
    if (NameHasBidiOverride(p.filename().wstring())) {
        out.push_back({95, "RLO/Bidi name", fname, spath,
            "Filename contains a right-to-left override that hides its real extension."});
    }

    // 2) Double extension: <name>.<data>.<exec>  e.g. report.pdf.exe
    {
        std::string inner = LowerExt(fs::path(Utf8(p.stem().wstring())));
        if (IsExecExt(ext) && !inner.empty() && IsDataExt(inner)) {
            out.push_back({90, "Double extension", fname, spath,
                "Double extension '." + inner + "." + ext +
                "': an executable posing as a " + inner + " file."});
        }
    }

    // 3) Hidden + System attributes on a user file.
    const DWORD attr = GetFileAttributesW(wpath.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES &&
        (attr & FILE_ATTRIBUTE_HIDDEN) && (attr & FILE_ATTRIBUTE_SYSTEM)) {
        out.push_back({55, "Hidden+System", fname, spath,
            "File carries Hidden+System attributes (invisible in Explorer by default)."});
    }

    // 4) Data extension but the content is a Windows executable (MZ/PE).
    if (IsDataExt(ext)) {
        unsigned char m[8] = {};
        const size_t n = ReadMagic(p, m, sizeof(m));
        if (n >= 2 && m[0] == 'M' && m[1] == 'Z') {
            out.push_back({92, "Fake data file", fname, spath,
                "Extension ." + ext + " but the bytes are a Windows executable (MZ/PE)."});
        }
    }

    // 5) Alternate Data Stream carrying hidden data.
    if (const std::string extra = FindExtraStream(wpath); !extra.empty()) {
        out.push_back({60, "Alternate Data Stream", fname, spath,
            "Hidden data stream (ADS) '" + extra + "' attached to this file."});
    }
}

QColor RiskColor(int risk) {
    if (risk >= 85) return QColor(0xFF, 0x5A, 0x6A);
    if (risk >= 55) return QColor(0xFF, 0x7A, 0x00);
    return QColor(0xE6, 0xC2, 0x4A);
}

} // namespace

QWidget* BuildHiddenHuntPage(QWidget* parent) {
    (void)parent; // page is reparented into the QStackedWidget by the caller
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(14);

    // Header
    auto* title = new QLabel(QString::fromUtf8("Hidden / Masqueraded Malware Hunt"), page);
    title->setStyleSheet("color:#ECE4DA; font-size:28px; font-weight:700; background:transparent;");
    root->addWidget(title);
    auto* sub = new QLabel(QString::fromUtf8(
        "Finds files disguised as data or hidden on the device: double extensions, "
        "RLO name tricks, fake data files (PE), Hidden+System, Alternate Data Streams."), page);
    sub->setStyleSheet("color:#8B7355; font-size:9pt; background:transparent;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    // Control row
    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(12);
    auto* hunt_btn = new QPushButton(QString::fromUtf8("Choose folder & hunt"), page);
    hunt_btn->setCursor(Qt::PointingHandCursor);
    hunt_btn->setStyleSheet(
        "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #FF7A00);"
        " border:none; border-radius:10px; color:#fff; font-size:10.5pt; font-weight:700; padding:10px 26px; }"
        "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9B3D,stop:1 #FF7A00); }"
        "QPushButton:disabled { background:#33261A; color:#8B7355; }");
    ctl->addWidget(hunt_btn);

    // Stop: this page's worker polls `scanning`, so clearing it cancels the walk.
    auto* stop_btn = new QPushButton(QString::fromUtf8("Stop"), page);
    stop_btn->setCursor(Qt::PointingHandCursor);
    stop_btn->setEnabled(false);
    stop_btn->setStyleSheet(
        "QPushButton { background:#241708; border:1px solid #FBBF24; border-radius:10px;"
        " color:#FBBF24; font-size:10pt; font-weight:700; padding:10px 20px; }"
        "QPushButton:hover { background:#33261A; }"
        "QPushButton:disabled { background:#241708; color:#8B7355; border-color:#33261A; }");
    ctl->addWidget(stop_btn);

    auto* status = new QLabel(QString::fromUtf8("Idle. Pick a folder to scan."), page);
    status->setStyleSheet("color:#C7B6A2; font-size:9.5pt; background:transparent;");
    ctl->addWidget(status, 1);
    root->addLayout(ctl);

    // Results table
    auto* table = new QTableWidget(0, 5, page);
    table->setHorizontalHeaderLabels({"Risk", "Type", "File", "Path", "Detail"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setStyleSheet(
        theme::TableQss());
    {
        auto* h = table->horizontalHeader();
        h->setStretchLastSection(false);
        h->setSectionResizeMode(0, QHeaderView::ResizeToContents); // Risk
        h->setSectionResizeMode(1, QHeaderView::ResizeToContents); // Type
        h->setSectionResizeMode(2, QHeaderView::ResizeToContents); // File
        h->setSectionResizeMode(3, QHeaderView::Stretch);          // Path
        h->setSectionResizeMode(4, QHeaderView::Stretch);          // Detail
    }
    root->addWidget(table, 1);

    // Reveal in Explorer on double-click.
    QObject::connect(table, &QTableWidget::cellDoubleClicked, table, [table](int row, int) {
        auto* item = table->item(row, 3);
        if (!item) return;
        const std::wstring wp = item->text().toStdWString();
        if (PIDLIST_ABSOLUTE pidl = ILCreateFromPathW(wp.c_str())) {
            SHOpenFolderAndSelectItems(pidl, 0, nullptr, 0);
            ILFree(pidl);
        }
    });

    // Shared scan state (survives for the app lifetime alongside the widgets).
    ArmQuitGuard(page);
    auto scanning = std::make_shared<std::atomic<bool>>(false);
    auto scanned  = std::make_shared<std::atomic<long long>>(0);
    auto flagged  = std::make_shared<std::atomic<long long>>(0);

    auto addRow = [table](const HiddenFinding& f) {
        const int row = table->rowCount();
        table->insertRow(row);
        QString bg; if (f.risk >= 90) bg = "#33261A"; else if (f.risk >= 70) bg = "#33261A"; else if (f.risk >= 50) bg = "#33261A"; else bg = "#33261A";
        auto* risk = new QTableWidgetItem(QString::number(f.risk));
        risk->setForeground(RiskColor(f.risk)); risk->setBackground(QColor(bg));
        table->setItem(row, 0, risk);
        auto* type = new QTableWidgetItem(QString::fromStdString(f.type));
        type->setForeground(RiskColor(f.risk)); type->setBackground(QColor(bg));
        table->setItem(row, 1, type);
        auto* fname = new QTableWidgetItem(QString::fromStdString(f.filename)); fname->setBackground(QColor(bg));
        table->setItem(row, 2, fname);
        auto* path = new QTableWidgetItem(QString::fromStdString(f.path)); path->setBackground(QColor(bg));
        table->setItem(row, 3, path);
        auto* detail = new QTableWidgetItem(QString::fromStdString(f.detail)); detail->setBackground(QColor(bg));
        table->setItem(row, 4, detail);
    };

    QObject::connect(hunt_btn, &QPushButton::clicked, page,
            [page, hunt_btn, status, table, scanning, scanned, flagged, addRow]() {
        if (scanning->load()) return;
        const QString dir = QFileDialog::getExistingDirectory(
            page, QString::fromUtf8("Choose folder to hunt"), QString(),
            QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
        if (dir.isEmpty()) return;

        table->setRowCount(0);
        scanned->store(0);
        flagged->store(0);
        scanning->store(true);
        hunt_btn->setEnabled(false);
        status->setText(QString::fromUtf8("Scanning: ") + dir);

        const std::wstring root = dir.toStdWString();
        std::thread([root, status, table, scanning, scanned, flagged, addRow]() {
            std::error_code ec;
            fs::recursive_directory_iterator it(
                fs::path(root), fs::directory_options::skip_permission_denied, ec);
            const fs::recursive_directory_iterator end;
            for (; !ec && it != end; it.increment(ec)) {
                if (!scanning->load() || AppQuitting().load()) break;
                std::error_code fec;
                if (it->is_symlink(fec)) { it.disable_recursion_pending(); continue; }
                if (!it->is_regular_file(fec) || fec) continue;

                scanned->fetch_add(1);
                std::vector<HiddenFinding> found;
                try {
                    AnalyzeFile(it->path(), found);
                } catch (...) { /* skip files we cannot read */ }

                for (auto& f : found) {
                    flagged->fetch_add(1);
                    QMetaObject::invokeMethod(table, [addRow, f]() { addRow(f); },
                                              Qt::QueuedConnection);
                }
                // Light progress heartbeat every 400 files.
                if (scanned->load() % 400 == 0) {
                    const long long sc = scanned->load(), fl = flagged->load();
                    QMetaObject::invokeMethod(status, [status, sc, fl]() {
                        status->setText(QString::fromUtf8("Scanning... %1 files, %2 suspicious")
                                            .arg(sc).arg(fl));
                    }, Qt::QueuedConnection);
                }
            }

            const long long sc = scanned->load(), fl = flagged->load();
            scanning->store(false);
            if (!AppQuitting().load()) {
                QMetaObject::invokeMethod(status, [status, sc, fl]() {
                    status->setText(QString::fromUtf8("Done. Scanned %1 files, %2 suspicious.")
                                        .arg(sc).arg(fl));
                }, Qt::QueuedConnection);
            }
        }).detach();
    });

    // Clean + Export (shared helper), inserted before the status label so the
    // control row reads: Hunt | Stop | Clean | Export | status.
    auto* clean_btn  = MakeCleanButton(page, table, status);
    auto* export_btn = MakeExportButton(page, table,
                                        QString::fromUtf8("hidden_findings.csv"), status);
    ctl->insertWidget(2, clean_btn);
    ctl->insertWidget(3, export_btn);

    // Stop: clear the flag the worker polls.
    QObject::connect(stop_btn, &QPushButton::clicked, page, [stop_btn, status, scanning] {
        if (!scanning->load()) return;
        scanning->store(false);
        stop_btn->setEnabled(false);
        status->setText(QString::fromUtf8("Stopping..."));
    });

    // One timer keeps every button in sync with scan/result state.
    auto* sync = new QTimer(page);
    sync->setInterval(300);
    QObject::connect(sync, &QTimer::timeout, hunt_btn,
                     [hunt_btn, stop_btn, clean_btn, export_btn, table, scanning]() {
        const bool busy = scanning->load();
        const bool has_rows = table->rowCount() > 0;
        hunt_btn->setEnabled(!busy);
        stop_btn->setEnabled(busy);
        clean_btn->setEnabled(!busy && has_rows);
        export_btn->setEnabled(!busy && has_rows);
    });
    sync->start();

    return page;
}

} // namespace avdashboard
