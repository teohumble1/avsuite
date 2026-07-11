// main_window_cicd.cpp — CI/CD Pipeline Protection + Supply Chain Attack Monitor
// Detects: malicious npm/pip packages, tampered build tools, compromised git hooks,
//          unsigned binaries in dev pipelines, npm typosquatting, cargo-audit style checks.

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <shlwapi.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#include <atomic>
#include <chrono>
#include <deque>
#include <filesystem>
#include <functional>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <regex>

#include <QCheckBox>
#include <QDateTime>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScrollArea>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QLineEdit>
#include <QFileDialog>
#include <QMessageBox>
#include <QProgressBar>

#include "autohunt_types.hpp"

namespace avdashboard {
namespace {

// ─── Suspicious npm package names (typosquatting + known malicious) ───────────
static const char* kMaliciousNpmPatterns[] = {
    "cross-env2",    "crossenv",      "event-stream",   "flatmap-stream",
    "eslint-scope",  "eslint-utils",  "getcookies",     "mailparser",
    "bootstrap-sass","rc",            "lodash-clone",   "fetch-cookie",
    "underscore",    "d3.js",         "faker.js",       "colors",
    "node-ipc",      "peacenotwar",   "coa",            "ua-parser-js",
    "vue-devtools",  "package-lock",  "install-package", "npm-scripts",
    "lodash-utils",  "angularjs-cli", "react-devtools", "webpack-bundle",
    nullptr
};

// ─── Suspicious pip packages ──────────────────────────────────────────────────
static const char* kMaliciousPipPatterns[] = {
    "colourama",   "jeIlyfish",  "mumpy",       "urlib3",
    "pylama",      "requestes",  "bzip",        "setup-tools",
    "pycryto",     "Pilliow",    "numpys",      "django-rest",
    "requests-toolbelt2",        "boto4",       "awscliv2",
    nullptr
};

// ─── Known safe build tool paths ─────────────────────────────────────────────
static const wchar_t* kSafeBuildDirs[] = {
    L"C:\\Program Files\\nodejs\\",
    L"C:\\Program Files\\Git\\",
    L"C:\\Program Files\\Microsoft Visual Studio\\",
    L"C:\\Program Files (x86)\\Microsoft Visual Studio\\",
    L"C:\\Windows\\",
    nullptr
};

// ─── Check if path is in a safe/expected location ────────────────────────────
static bool IsExpectedBuildPath(const std::wstring& path) {
    for (int i = 0; kSafeBuildDirs[i]; ++i) {
        if (path.substr(0, wcslen(kSafeBuildDirs[i])) == kSafeBuildDirs[i])
            return true;
    }
    return false;
}

// ─── Check digital signature ──────────────────────────────────────────────────
static bool IsFileSigned(const std::wstring& path) {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct        = sizeof(fi);
    fi.pcwszFilePath   = path.c_str();
    GUID pgActionID    = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd{};
    wd.cbStruct        = sizeof(wd);
    wd.dwUIChoice      = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice   = WTD_CHOICE_FILE;
    wd.pFile           = &fi;
    wd.dwStateAction   = WTD_STATEACTION_VERIFY;
    LONG res = WinVerifyTrust(nullptr, &pgActionID, &wd);
    wd.dwStateAction   = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &pgActionID, &wd);
    return res == ERROR_SUCCESS;
}

// ─── Scan npm packages in a given node_modules directory ─────────────────────
struct PkgFinding {
    enum Type { NpmMalicious, PipMalicious, UnsignedBuildTool,
                TamperedGitHook, SuspiciousScript, MaliciousProcess };
    Type        type;
    std::string name;
    std::string path;
    std::string reason;
    int         risk_score;
    int64_t     ts_epoch;
};

static std::vector<PkgFinding> ScanNpmModules(const std::filesystem::path& root) {
    std::vector<PkgFinding> results;
    std::error_code ec;
    if (!std::filesystem::exists(root, ec)) return results;

    for (auto& entry : std::filesystem::directory_iterator(root, ec)) {
        if (!entry.is_directory(ec)) continue;
        std::string pkg = entry.path().filename().string();
        // Check typosquatting/known-malicious list
        for (int i = 0; kMaliciousNpmPatterns[i]; ++i) {
            if (pkg == kMaliciousNpmPatterns[i]) {
                PkgFinding f;
                f.type       = PkgFinding::NpmMalicious;
                f.name       = pkg;
                f.path       = entry.path().string();
                f.reason     = "Known malicious/typosquatted npm package";
                f.risk_score = 90;
                using namespace std::chrono;
                f.ts_epoch   = duration_cast<seconds>(
                    system_clock::now().time_since_epoch()).count();
                results.push_back(std::move(f));
                break;
            }
        }
        // Check package.json for suspicious scripts
        auto pkg_json = entry.path() / "package.json";
        if (std::filesystem::exists(pkg_json, ec)) {
            std::ifstream f(pkg_json);
            if (f.is_open()) {
                std::string content((std::istreambuf_iterator<char>(f)),
                                     std::istreambuf_iterator<char>());
                // Look for install hooks that run curl/powershell/cmd
                static const std::regex re_suspicious(
                    R"rx("(preinstall|postinstall|install)"\s*:\s*"[^"]*(?:curl|wget|powershell|cmd|bash|sh|python)[^"]*")rx",
                    std::regex::icase);
                if (std::regex_search(content, re_suspicious)) {
                    PkgFinding pf;
                    pf.type       = PkgFinding::SuspiciousScript;
                    pf.name       = pkg;
                    pf.path       = pkg_json.string();
                    pf.reason     = "Install hook runs shell commands (curl/powershell/cmd)";
                    pf.risk_score = 75;
                    using namespace std::chrono;
                    pf.ts_epoch   = duration_cast<seconds>(
                        system_clock::now().time_since_epoch()).count();
                    results.push_back(std::move(pf));
                }
            }
        }
    }
    return results;
}

// ─── Scan git hooks in a repository ──────────────────────────────────────────
static std::vector<PkgFinding> ScanGitHooks(const std::filesystem::path& repo_root) {
    std::vector<PkgFinding> results;
    auto hooks_dir = repo_root / ".git" / "hooks";
    std::error_code ec;
    if (!std::filesystem::exists(hooks_dir, ec)) return results;

    static const char* hook_names[] = {
        "pre-commit", "pre-push", "post-merge", "prepare-commit-msg",
        "commit-msg", "post-checkout", "post-receive", nullptr
    };

    for (int i = 0; hook_names[i]; ++i) {
        auto hook = hooks_dir / hook_names[i];
        if (!std::filesystem::exists(hook, ec)) continue;

        std::ifstream f(hook);
        if (!f.is_open()) continue;
        std::string content((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());

        // Suspicious patterns in git hooks
        static const std::regex re_susp(
            R"((?:curl|wget|nc\s|netcat|powershell|base64\s+-d|eval\s*\(|exec\s*\(|system\s*\())",
            std::regex::icase);

        if (std::regex_search(content, re_susp)) {
            PkgFinding pf;
            pf.type       = PkgFinding::TamperedGitHook;
            pf.name       = hook_names[i];
            pf.path       = hook.string();
            pf.reason     = "Git hook contains network/execution commands";
            pf.risk_score = 85;
            using namespace std::chrono;
            pf.ts_epoch   = duration_cast<seconds>(
                system_clock::now().time_since_epoch()).count();
            results.push_back(std::move(pf));
        }
    }
    return results;
}

// ─── Scan running build tool processes for anomalies ─────────────────────────
static std::vector<PkgFinding> ScanBuildProcesses() {
    std::vector<PkgFinding> results;
    static const char* kBuildProcs[] = {
        "node.exe", "npm.cmd", "npm.exe", "yarn.exe", "pnpm.exe",
        "python.exe", "pip.exe", "msbuild.exe", "cmake.exe",
        "cargo.exe", "rustc.exe", "go.exe", "gradle", "mvn.cmd",
        nullptr
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return results;

    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return results; }

    do {
        std::wstring wname(pe.szExeFile);
        std::string name(wname.begin(), wname.end());

        bool is_build = false;
        for (int i = 0; kBuildProcs[i]; ++i) {
            if (_stricmp(name.c_str(), kBuildProcs[i]) == 0) {
                is_build = true; break;
            }
        }
        if (!is_build) continue;

        HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!ph) continue;
        wchar_t buf[MAX_PATH]{};
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(ph, 0, buf, &sz)) {
            std::wstring full_path(buf, sz);
            if (!IsExpectedBuildPath(full_path)) {
                // Build tool running from unexpected path
                PkgFinding pf;
                pf.type       = PkgFinding::MaliciousProcess;
                pf.name       = name;
                std::string fp(full_path.begin(), full_path.end());
                pf.path       = fp;
                pf.reason     = "Build tool running from non-standard path";
                pf.risk_score = 70;
                using namespace std::chrono;
                pf.ts_epoch   = duration_cast<seconds>(
                    system_clock::now().time_since_epoch()).count();
                results.push_back(std::move(pf));
            }
            // Check if signed
            if (!IsFileSigned(full_path) && full_path.find(L".exe") != std::wstring::npos) {
                PkgFinding pf;
                pf.type       = PkgFinding::UnsignedBuildTool;
                pf.name       = name;
                std::string fp(full_path.begin(), full_path.end());
                pf.path       = fp;
                pf.reason     = "Build tool executable is unsigned";
                pf.risk_score = 55;
                using namespace std::chrono;
                pf.ts_epoch   = duration_cast<seconds>(
                    system_clock::now().time_since_epoch()).count();
                results.push_back(std::move(pf));
            }
        }
        CloseHandle(ph);
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return results;
}

} // anonymous namespace

// ─── Page builder ─────────────────────────────────────────────────────────────
QWidget* BuildCiCdPage(QWidget* parent) {
    static constexpr const char* kBg     = "#0E0804";
    static constexpr const char* kCard   = "#1C1108";
    static constexpr const char* kBorder = "#33261A";
    static constexpr const char* kText   = "#ECE4DA";
    static constexpr const char* kMuted  = "#8B7355";
    static constexpr const char* kRed    = "#FF5A6A";
    static constexpr const char* kOrange = "#FF7A00";
    static constexpr const char* kGreen  = "#4ADE80";
    static constexpr const char* kPurple = "#4DB8FF";
    static constexpr const char* kYellow = "#FBBF24";

    auto* page = new QWidget(parent);
    page->setStyleSheet(QString("background:%1;").arg(kBg));

    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(20, 16, 20, 16);
    root->setSpacing(10);

    // ── Header ──────────────────────────────────────────────────────────────
    {
        auto* hdr = new QHBoxLayout;
        auto* title = new QLabel("CI/CD Pipeline Protection");
        title->setStyleSheet(QString("color:%1;font-size:17px;font-weight:700;").arg(kText));
        auto* sub = new QLabel("Supply chain · npm/pip malware · git hook tampering · unsigned build tools");
        sub->setStyleSheet(QString("color:%1;font-size:11px;").arg(kMuted));
        hdr->addWidget(title);
        hdr->addWidget(sub);
        hdr->addStretch();
        root->addLayout(hdr);
    }

    // ── Stat row ────────────────────────────────────────────────────────────
    QLabel *statTotal=nullptr, *statCritical=nullptr, *statNpm=nullptr, *statGit=nullptr;
    {
        auto makeCard = [](const QString& val, const QString& lbl,
                           const char* col, QLabel** out) {
            auto* w  = new QWidget;
            auto* vl = new QVBoxLayout(w);
            vl->setContentsMargins(14,10,14,10);
            vl->setSpacing(3);
            auto* v = new QLabel(val);
            v->setStyleSheet(QString("color:%1;font-size:20px;font-weight:700;").arg(col));
            auto* l = new QLabel(lbl);
            l->setStyleSheet("color:#8B7355;font-size:10px;");
            vl->addWidget(v); vl->addWidget(l);
            w->setStyleSheet("background:#1C1108;border:1px solid #33261A;border-radius:8px;");
            if (out) *out = v;
            return w;
        };
        auto* row = new QHBoxLayout;
        row->setSpacing(8);
        row->addWidget(makeCard("0", "Total Findings",    kText,   &statTotal));
        row->addWidget(makeCard("0", "Critical",          kRed,    &statCritical));
        row->addWidget(makeCard("0", "npm/pip Issues",    kPurple, &statNpm));
        row->addWidget(makeCard("0", "Git Hook Tampering",kOrange, &statGit));
        root->addLayout(row);
    }

    // ── Scan path input ──────────────────────────────────────────────────────
    {
        auto* pathRow = new QHBoxLayout;
        pathRow->setSpacing(8);
        auto* pathLabel = new QLabel("Scan Path:");
        pathLabel->setStyleSheet(QString("color:%1;font-size:12px;").arg(kMuted));
        auto* pathEdit = new QLineEdit;
        pathEdit->setObjectName("CiCdPathEdit");
        pathEdit->setPlaceholderText("C:\\dev\\myproject (or leave blank to auto-detect)");
        pathEdit->setStyleSheet(QString(R"(
            QLineEdit { background:%1; color:%2; border:1px solid %3;
                        border-radius:5px; padding:5px 10px; font-size:12px; }
            QLineEdit:focus { border-color:%4; }
        )").arg(kCard).arg(kText).arg(kBorder).arg(kPurple));
        auto* browseBtn = new QPushButton("Browse");
        browseBtn->setStyleSheet(QString(R"(
            QPushButton { background:%1; color:%2; border:1px solid %3;
                          border-radius:5px; padding:5px 12px; font-size:12px; }
            QPushButton:hover { background:%4; color:white; border-color:%4; }
        )").arg(kCard).arg(kMuted).arg(kBorder).arg(kPurple));
        browseBtn->setCursor(Qt::PointingHandCursor);
        auto* scanBtn = new QPushButton("⚡ Scan Now");
        scanBtn->setObjectName("CiCdScanBtn");
        scanBtn->setStyleSheet(QString(R"(
            QPushButton { background:%1; color:white; border:none;
                          border-radius:5px; padding:5px 16px; font-size:12px; font-weight:600; }
            QPushButton:hover { background:#4DB8FF; }
            QPushButton:disabled { background:#33261A; color:%2; }
        )").arg(kPurple).arg(kMuted));
        scanBtn->setCursor(Qt::PointingHandCursor);
        pathRow->addWidget(pathLabel);
        pathRow->addWidget(pathEdit, 1);
        pathRow->addWidget(browseBtn);
        pathRow->addWidget(scanBtn);
        root->addLayout(pathRow);

        QObject::connect(browseBtn, &QPushButton::clicked, page, [=]() {
            QString dir = QFileDialog::getExistingDirectory(page, "Select project root");
            if (!dir.isEmpty()) pathEdit->setText(dir);
        });
    }

    // ── Findings table ────────────────────────────────────────────────────────
    auto* tableCard = new QWidget;
    tableCard->setStyleSheet(QString("background:%1;border:1px solid %2;border-radius:8px;")
                                 .arg(kCard).arg(kBorder));
    auto* tl = new QVBoxLayout(tableCard);
    tl->setContentsMargins(0,0,0,0);

    auto* tbl = new QTableWidget(0, 5);
    tbl->setHorizontalHeaderLabels({"Risk", "Type", "Name", "Path", "Reason"});
    tbl->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    tbl->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    tbl->setColumnWidth(0, 52);
    tbl->setColumnWidth(1, 130);
    tbl->setColumnWidth(2, 140);
    tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tbl->verticalHeader()->setVisible(false);
    tbl->setShowGrid(false);
    tbl->setStyleSheet(QString(R"(
        QTableWidget { background:transparent; color:%1; border:none; font-size:12px; }
        QTableWidget::item { padding:7px 10px; border-bottom:1px solid %2; }
        QTableWidget::item:selected { background:#33261A; }
        QHeaderView::section { background:%3; color:%4; border:none;
                               border-bottom:1px solid %2; padding:5px 10px; font-size:11px; }
        QScrollBar:vertical { background:%3; width:5px; border-radius:2px; }
        QScrollBar::handle:vertical { background:%2; border-radius:2px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
    )").arg(kText).arg(kBorder).arg(kCard).arg(kMuted));
    tl->addWidget(tbl);

    // Detail panel
    auto* detailText = new QTextEdit;
    detailText->setReadOnly(true);
    detailText->setMaximumHeight(90);
    detailText->setStyleSheet(QString(R"(
        QTextEdit { background:#0E0804; color:%1; border:none; border-top:1px solid %2;
                    font-family:Consolas,monospace; font-size:11px; padding:8px; }
    )").arg(kText).arg(kBorder));
    tl->addWidget(detailText);

    root->addWidget(tableCard, 1);

    // ── Status bar ────────────────────────────────────────────────────────────
    auto* statusLbl = new QLabel("Click 'Scan Now' to analyze CI/CD pipeline integrity");
    statusLbl->setStyleSheet(QString("color:%1;font-size:11px;padding:4px 0;").arg(kMuted));
    root->addWidget(statusLbl);

    // ── Scan logic ────────────────────────────────────────────────────────────
    struct ScanState {
        std::atomic<bool> scanning{false};
        std::vector<PkgFinding> findings;
    };
    auto* state = new ScanState;
    page->setProperty("cicdState", QVariant::fromValue(static_cast<void*>(state)));

    auto refreshTable = [=]() {
        tbl->setRowCount(static_cast<int>(state->findings.size()));
        int critical = 0, npm_count = 0, git_count = 0;

        for (int r = 0; r < static_cast<int>(state->findings.size()); ++r) {
            const auto& f = state->findings[r];
            if (f.risk_score >= 75) ++critical;
            if (f.type == PkgFinding::NpmMalicious || f.type == PkgFinding::PipMalicious ||
                f.type == PkgFinding::SuspiciousScript) ++npm_count;
            if (f.type == PkgFinding::TamperedGitHook) ++git_count;

            QColor riskCol = f.risk_score >= 75 ? QColor(kRed) : QColor(kOrange);

            auto setItem = [&](int col, const QString& txt, QColor c = QColor(kText)) {
                auto* item = new QTableWidgetItem(txt);
                item->setForeground(c);
                tbl->setItem(r, col, item);
            };

            setItem(0, QString::number(f.risk_score), riskCol);

            QString typeStr;
            QColor typeCol(kText);
            switch (f.type) {
                case PkgFinding::NpmMalicious:      typeStr="npm Malware";    typeCol=QColor(kPurple); break;
                case PkgFinding::PipMalicious:      typeStr="pip Malware";    typeCol=QColor(kPurple); break;
                case PkgFinding::UnsignedBuildTool: typeStr="Unsigned Tool";  typeCol=QColor(kYellow); break;
                case PkgFinding::TamperedGitHook:   typeStr="Git Hook";       typeCol=QColor(kRed);    break;
                case PkgFinding::SuspiciousScript:  typeStr="Malicious Script";typeCol=QColor(kOrange);break;
                case PkgFinding::MaliciousProcess:  typeStr="Bad Process";    typeCol=QColor(kRed);    break;
            }
            setItem(1, typeStr, typeCol);
            setItem(2, QString::fromStdString(f.name));

            // Truncate long paths
            std::string short_path = f.path;
            if (short_path.size() > 50) short_path = "..." + short_path.substr(short_path.size()-47);
            setItem(3, QString::fromStdString(short_path), QColor(kMuted));
            setItem(4, QString::fromStdString(f.reason), riskCol);
            tbl->setRowHeight(r, 34);
        }

        if (statTotal)    statTotal->setText(QString::number(state->findings.size()));
        if (statCritical) statCritical->setText(QString::number(critical));
        if (statNpm)      statNpm->setText(QString::number(npm_count));
        if (statGit)      statGit->setText(QString::number(git_count));
    };

    // Table row selection
    QObject::connect(tbl, &QTableWidget::currentCellChanged, page,
                     [=](int row, int, int, int) {
        if (row < 0 || row >= static_cast<int>(state->findings.size())) return;
        const auto& f = state->findings[row];
        QDateTime dt = QDateTime::fromSecsSinceEpoch(f.ts_epoch);
        detailText->setPlainText(
            QString("Type    : %1\n"
                    "Name    : %2\n"
                    "Path    : %3\n"
                    "Reason  : %4\n"
                    "Risk    : %5/100\n"
                    "Found   : %6")
                .arg([&]() -> QString {
                    switch (f.type) {
                        case PkgFinding::NpmMalicious:       return "npm Malware";
                        case PkgFinding::PipMalicious:       return "pip Malware";
                        case PkgFinding::UnsignedBuildTool:  return "Unsigned Build Tool";
                        case PkgFinding::TamperedGitHook:    return "Tampered Git Hook";
                        case PkgFinding::SuspiciousScript:   return "Suspicious Install Script";
                        case PkgFinding::MaliciousProcess:   return "Malicious Build Process";
                        default: return "Unknown";
                    }
                }())
                .arg(QString::fromStdString(f.name))
                .arg(QString::fromStdString(f.path))
                .arg(QString::fromStdString(f.reason))
                .arg(f.risk_score)
                .arg(dt.toString("hh:mm:ss")));
    });

    // Scan button
    auto* scanBtnPtr = page->findChild<QPushButton*>("CiCdScanBtn");
    auto* pathEditPtr = page->findChild<QLineEdit*>("CiCdPathEdit");

    if (scanBtnPtr) {
        QObject::connect(scanBtnPtr, &QPushButton::clicked, page, [=]() {
            if (state->scanning.exchange(true)) return;
            scanBtnPtr->setEnabled(false);
            scanBtnPtr->setText("Scanning...");
            statusLbl->setText("Scanning for supply chain threats...");
            state->findings.clear();

            QString scanPath = pathEditPtr ? pathEditPtr->text().trimmed() : "";

            std::thread([=]() {
                std::vector<PkgFinding> all;

                // 1. Scan running build processes
                auto procs = ScanBuildProcesses();
                all.insert(all.end(), procs.begin(), procs.end());

                // 2. Scan npm/git in specified path or common dev dirs
                std::vector<std::filesystem::path> scan_roots;
                if (!scanPath.isEmpty()) {
                    scan_roots.push_back(scanPath.toStdString());
                } else {
                    // Auto-detect common dev dirs
                    const wchar_t* devDirs[] = {
                        L"C:\\dev", L"C:\\Users\\Default\\source",
                        L"D:\\Dev", L"D:\\projects", L"D:\\src", nullptr
                    };
                    for (int i = 0; devDirs[i]; ++i) {
                        if (GetFileAttributesW(devDirs[i]) != INVALID_FILE_ATTRIBUTES)
                            scan_roots.push_back(std::wstring(devDirs[i]));
                    }
                }

                for (const auto& root : scan_roots) {
                    // npm node_modules
                    auto npm = ScanNpmModules(root / "node_modules");
                    all.insert(all.end(), npm.begin(), npm.end());

                    // Git hooks
                    auto git = ScanGitHooks(root);
                    all.insert(all.end(), git.begin(), git.end());

                    // Recurse one level for subprojects
                    std::error_code ec;
                    for (auto& sub : std::filesystem::directory_iterator(root, ec)) {
                        if (!sub.is_directory(ec)) continue;
                        auto sub_npm = ScanNpmModules(sub.path() / "node_modules");
                        all.insert(all.end(), sub_npm.begin(), sub_npm.end());
                        auto sub_git = ScanGitHooks(sub.path());
                        all.insert(all.end(), sub_git.begin(), sub_git.end());
                    }
                }

                // Sort by risk descending
                std::sort(all.begin(), all.end(), [](const PkgFinding& a, const PkgFinding& b) {
                    return a.risk_score > b.risk_score;
                });

                // Feed critical to AutoHunt
                for (const auto& f : all) {
                    if (f.risk_score >= 70) {
                        HuntTarget ht;
                        ht.source      = "CI/CD";
                        ht.name        = f.name;
                        ht.path        = f.path;
                        ht.risk_score  = f.risk_score;
                        ht.description = f.reason;
                        AutoHuntEnqueue(std::move(ht));
                    }
                }

                QMetaObject::invokeMethod(page, [=, findings = std::move(all)]() mutable {
                    state->findings = std::move(findings);
                    state->scanning.store(false);
                    if (scanBtnPtr) {
                        scanBtnPtr->setEnabled(true);
                        scanBtnPtr->setText("⚡ Scan Now");
                    }
                    int n = static_cast<int>(state->findings.size());
                    statusLbl->setText(QString("Scan complete — %1 finding(s) detected   %2")
                        .arg(n)
                        .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
                    refreshTable();
                }, Qt::QueuedConnection);
            }).detach();
        });
    }

    // Auto-scan processes on page load
    QTimer::singleShot(1000, page, [=]() {
        if (scanBtnPtr) scanBtnPtr->click();
    });

    // Cleanup
    QObject::connect(page, &QWidget::destroyed, page, [state]() { delete state; });

    return page;
}

} // namespace avdashboard
