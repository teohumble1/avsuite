// main_window_supplychain.cpp — Supply-chain & infostealer defense scanner.
//
// Scans a project/dev folder for indicators of the modern attack chain:
//   * Hijacked npm packages: malicious pre/post-install scripts in package.json
//   * Malicious VS Code tasks: .vscode/tasks.json auto-running on folderOpen or
//     launching interpreters (the "VS Code Tasks deploy Python infostealer" TTP)
//   * Python / JS infostealers: exfil webhooks, browser credential/cookie theft,
//     obfuscated exec(base64(...)), curl|bash pipe-to-shell installers
//
// Detection-only (defensive). ASCII labels (MSVC builds without /utf-8).

#include "main_window.hpp"
#include "theme.hpp"
#include "av_quit_guard.hpp"
#include "hunt_toolbar.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <windows.h>
#include <ShlObj.h>
#pragma comment(lib, "shell32.lib")

#include <atomic>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace avdashboard {
namespace {

struct ScFinding {
    int         risk = 0;
    std::string type;
    std::string filename;
    std::string path;
    std::string detail;
};

struct ScRule {
    const char* id;
    const char* cls;
    int         risk;
    const char* detail;
    QRegularExpression re;
};

// Content rules applied to inspected text files.
const std::vector<ScRule>& Rules() {
    static const std::vector<ScRule> rules = [] {
        auto R = [](const char* id, const char* cls, int risk, const char* detail, const char* pat) {
            return ScRule{ id, cls, risk, detail,
                QRegularExpression(QString::fromUtf8(pat),
                    QRegularExpression::CaseInsensitiveOption
                  | QRegularExpression::DotMatchesEverythingOption) };
        };
        std::vector<ScRule> v;
        // npm install hooks that pull/run code
        v.push_back(R("SC-NPM-001", "npm install hook", 88,
            "package.json (pre/post)install runs network/shell code",
            "\"(pre|post)?install\"\\s*:\\s*\"[^\"]*(curl|wget|node\\s+-e|base64|child_process|https?://|powershell|iwr|invoke-expression|\\.sh\\b)"));
        // VS Code auto-run tasks
        v.push_back(R("SC-VSC-001", "VSCode auto-task", 90,
            ".vscode task auto-runs when the folder is opened (runOn: folderOpen)",
            "\"runOn\"\\s*:\\s*\"folderOpen\""));
        v.push_back(R("SC-VSC-002", "VSCode task exec", 60,
            "VS Code task launches an interpreter/downloader",
            "\"command\"\\s*:\\s*\"(python3?|powershell|pwsh|cmd|bash|sh|node|curl|wget)\""));
        // Infostealer: exfil webhooks
        v.push_back(R("SC-EXF-001", "Exfil webhook", 90,
            "Data exfiltration to a chat webhook (Discord/Telegram/Slack)",
            "discord(app)?\\.com/api/webhooks|api\\.telegram\\.org/bot|hooks\\.slack\\.com/services"));
        // Infostealer: browser credential / cookie theft
        v.push_back(R("SC-STEAL-001", "Browser cred theft", 92,
            "Accesses browser saved credentials / cookies",
            "Login Data|cookies\\.sqlite|Google\\\\Chrome\\\\User Data|Local State|moz_cookies|win32crypt|CryptUnprotectData"));
        // Obfuscated exec
        v.push_back(R("SC-OBF-001", "Obfuscated exec", 85,
            "Executes decoded/obfuscated payload",
            "(exec|eval)\\s*\\(\\s*(base64\\.b64decode|atob|__import__\\(\\s*['\"]base64)"));
        v.push_back(R("SC-OBF-002", "Obfuscation", 55,
            "Char-code / long base64 blob (possible packed payload)",
            "String\\.fromCharCode\\((\\s*\\d+\\s*,){12,}|[A-Za-z0-9+/]{220,}={0,2}"));
        // Pipe-to-shell installer
        v.push_back(R("SC-PIPE-001", "Pipe-to-shell", 85,
            "Downloads and pipes straight into a shell",
            "(curl|wget)\\s+[^\\n|]*\\|\\s*(bash|sh)\\b|(iwr|invoke-webrequest)[^\\n|]*\\|\\s*iex"));
        return v;
    }();
    return rules;
}

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

// Only inspect text/config/script files (and specific config names) to stay fast.
bool ShouldInspect(const fs::path& p) {
    const std::string ext = LowerExt(p);
    static const char* exts[] = { "json","js","ts","mjs","cjs","py","sh","ps1","bat",
                                  "cmd","yml","yaml","toml","rb","pl","php", nullptr };
    for (int i = 0; exts[i]; ++i) if (ext == exts[i]) return true;
    const std::string name = p.filename().string();
    return name == "package.json" || name == "tasks.json" || name == "launch.json";
}

QString ReadTextCapped(const fs::path& p, qint64 cap = 512 * 1024) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    std::string buf(static_cast<size_t>(cap), '\0');
    f.read(buf.data(), cap);
    buf.resize(static_cast<size_t>(f.gcount()));
    return QString::fromUtf8(buf.c_str(), static_cast<int>(buf.size()));
}

void AnalyzeFile(const fs::path& p, std::vector<ScFinding>& out) {
    if (!ShouldInspect(p)) return;
    const QString content = ReadTextCapped(p);
    if (content.isEmpty()) return;
    const std::string fname = Utf8(p.filename().wstring());
    const std::string spath = Utf8(p.wstring());

    // Check if file is minified/bundled/build artifact (context for obfuscation rule)
    const bool isMinified = (fname.find(".min.js") != std::string::npos ||
                             fname.find("bundle.js") != std::string::npos ||
                             fname.find("bundled") != std::string::npos);
    const bool isNodeModules = (spath.find("node_modules") != std::string::npos);
    const bool isBuildDir = (spath.find("\\dist\\") != std::string::npos ||
                             spath.find("/dist/") != std::string::npos ||
                             spath.find("\\build\\") != std::string::npos ||
                             spath.find("/build/") != std::string::npos);
    const bool hasSourcemap = content.contains("//# sourceMappingURL=");

    for (const auto& rule : Rules()) {
        // VS Code rules only make sense inside a tasks/launch/settings json.
        if ((std::string(rule.id).rfind("SC-VSC", 0) == 0) && fname.find("tasks.json") == std::string::npos
            && fname.find("launch.json") == std::string::npos)
            continue;

        if (rule.re.match(content).hasMatch()) {
            // Special handling for obfuscation rule (SC-OBF-002):
            // Long base64 blobs are normal in minified/bundled JS, don't report as high-risk
            if (std::string(rule.id) == "SC-OBF-002" && (isMinified || hasSourcemap || isBuildDir || isNodeModules)) {
                // Skip this rule for minified code with sourcemap (clear sign of legitimate build artifact)
                if (hasSourcemap) continue;
                // For build/node_modules, still report but at LOWER risk to differentiate from malware obfuscation
                // (user can still investigate if they're concerned)
                out.push_back({ 20, "Build artifact obfuscation", fname, spath,
                    "Long base64 blob in minified/bundled code (typical of production builds, low risk)" });
            } else {
                out.push_back({ rule.risk, rule.cls, fname, spath, rule.detail });
            }
        }
    }
}

QColor RiskColor(int r) {
    if (r >= 85) return QColor(0xFF, 0x3B, 0x50);
    if (r >= 55) return QColor(0xFF, 0x7A, 0x00);
    return QColor(0xE6, 0xC2, 0x4A);
}

} // namespace

QWidget* BuildSupplyChainPage(QWidget* parent) {
    (void)parent;
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(12);

    root->addWidget(theme::BuildPageHeader(
        "Supply-chain & Infostealer Defense",
        "Scans a project folder for hijacked npm packages (malicious install hooks), "
        "malicious VS Code tasks (auto-run on open), and Python/JS infostealers "
        "(exfil webhooks, browser credential theft, obfuscated exec, pipe-to-shell)."));

    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(theme::Space3);
    auto* scan_btn = new QPushButton(QString::fromUtf8("Choose project folder & scan"), page);
    scan_btn->setObjectName("PrimaryBtn");
    scan_btn->setCursor(Qt::PointingHandCursor);
    ctl->addWidget(scan_btn);

    // Stop: this page's worker polls `scanning`, so clearing it cancels the walk.
    auto* stop_btn = new QPushButton(QString::fromUtf8("Stop"), page);
    stop_btn->setCursor(Qt::PointingHandCursor);
    stop_btn->setEnabled(false);
    stop_btn->setStyleSheet(QString(
        "QPushButton { background:transparent; border:1px solid %1; border-radius:%2px;"
        " color:%1; font-size:%3px; font-weight:600; padding:9px 18px; }"
        "QPushButton:hover { background:rgba(251,191,36,0.12); }"
        "QPushButton:disabled { background:%4; color:%5; border-color:%6; }")
        .arg(theme::Warn).arg(theme::RadiusMd).arg(theme::FontBody)
        .arg(theme::Surface).arg(theme::Dim).arg(theme::Border));
    ctl->addWidget(stop_btn);

    auto* status = new QLabel(QString::fromUtf8("Idle. Pick a project/repo folder."), page);
    status->setStyleSheet(QString("color:%1; font-size:%2px; background:transparent;")
                              .arg(theme::Muted).arg(theme::FontBody));
    ctl->addWidget(status, 1);
    root->addLayout(ctl);

    auto* table = new QTableWidget(0, 4, page);
    table->setHorizontalHeaderLabels({"Risk", "Type", "File", "Detail"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setStyleSheet(theme::TableQss());
    {
        auto* h = table->horizontalHeader();
        h->setStretchLastSection(true);
        h->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(2, QHeaderView::Stretch);
    }
    root->addWidget(table, 1);

    QObject::connect(table, &QTableWidget::cellDoubleClicked, table, [table](int row, int) {
        auto* it = table->item(row, 2);
        if (!it) return;
        const std::wstring wp = it->data(Qt::UserRole).toString().toStdWString();
        if (PIDLIST_ABSOLUTE pidl = ILCreateFromPathW(wp.c_str())) {
            SHOpenFolderAndSelectItems(pidl, 0, nullptr, 0);
            ILFree(pidl);
        }
    });

    ArmQuitGuard(page);
    auto scanning = std::make_shared<std::atomic<bool>>(false);
    auto scanned  = std::make_shared<std::atomic<long long>>(0);
    auto flagged  = std::make_shared<std::atomic<long long>>(0);

    auto addRow = [table](const ScFinding& f) {
        const int row = table->rowCount();
        table->insertRow(row);
        QString bg; if (f.risk >= 90) bg = "#33261A"; else if (f.risk >= 70) bg = "#33261A"; else if (f.risk >= 50) bg = "#33261A"; else bg = "#33261A";
        auto* risk = new QTableWidgetItem(QString::number(f.risk));
        risk->setForeground(RiskColor(f.risk)); risk->setBackground(QColor(bg));
        table->setItem(row, 0, risk);
        auto* type = new QTableWidgetItem(QString::fromStdString(f.type));
        type->setForeground(RiskColor(f.risk)); type->setBackground(QColor(bg));
        table->setItem(row, 1, type);
        auto* file = new QTableWidgetItem(QString::fromStdString(f.filename));
        file->setData(Qt::UserRole, QString::fromStdString(f.path));
        file->setToolTip(QString::fromStdString(f.path)); file->setBackground(QColor(bg));
        table->setItem(row, 2, file);
        auto* detail = new QTableWidgetItem(QString::fromStdString(f.detail)); detail->setBackground(QColor(bg));
        table->setItem(row, 3, detail);
    };

    QObject::connect(scan_btn, &QPushButton::clicked, page,
            [page, scan_btn, status, table, scanning, scanned, flagged, addRow]() {
        if (scanning->load()) return;
        const QString dir = QFileDialog::getExistingDirectory(
            page, QString::fromUtf8("Choose project folder"), QString(),
            QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
        if (dir.isEmpty()) return;
        table->setRowCount(0);
        scanned->store(0);
        flagged->store(0);
        scanning->store(true);
        scan_btn->setEnabled(false);
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
                std::vector<ScFinding> found;
                try { AnalyzeFile(it->path(), found); } catch (...) {}
                for (auto& f : found) {
                    flagged->fetch_add(1);
                    QMetaObject::invokeMethod(table, [addRow, f]() { addRow(f); }, Qt::QueuedConnection);
                }
                if (scanned->load() % 300 == 0) {
                    const long long sc = scanned->load(), fl = flagged->load();
                    QMetaObject::invokeMethod(status, [status, sc, fl]() {
                        status->setText(QString::fromUtf8("Scanning... %1 files, %2 findings").arg(sc).arg(fl));
                    }, Qt::QueuedConnection);
                }
            }
            const long long sc = scanned->load(), fl = flagged->load();
            scanning->store(false);
            if (!AppQuitting().load()) {
                QMetaObject::invokeMethod(status, [status, sc, fl]() {
                    status->setText(QString::fromUtf8("Done. Scanned %1 files, %2 findings.").arg(sc).arg(fl));
                }, Qt::QueuedConnection);
            }
        }).detach();
    });

    // Clean + Export (shared helper): Scan | Stop | Clean | Export | status.
    auto* clean_btn  = MakeCleanButton(page, table, status);
    auto* export_btn = MakeExportButton(page, table,
                                        QString::fromUtf8("supplychain_findings.csv"), status);
    ctl->insertWidget(2, clean_btn);
    ctl->insertWidget(3, export_btn);

    QObject::connect(stop_btn, &QPushButton::clicked, page, [stop_btn, status, scanning] {
        if (!scanning->load()) return;
        scanning->store(false);
        stop_btn->setEnabled(false);
        status->setText(QString::fromUtf8("Stopping..."));
    });

    auto* sync = new QTimer(page);
    sync->setInterval(300);
    QObject::connect(sync, &QTimer::timeout, scan_btn,
                     [scan_btn, stop_btn, clean_btn, export_btn, table, scanning]() {
        const bool busy = scanning->load();
        const bool has_rows = table->rowCount() > 0;
        scan_btn->setEnabled(!busy);
        stop_btn->setEnabled(busy);
        clean_btn->setEnabled(!busy && has_rows);
        export_btn->setEnabled(!busy && has_rows);
    });
    sync->start();

    return page;
}

} // namespace avdashboard
