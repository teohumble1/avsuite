// main_window_dlp.cpp — DLP / data-leak monitor.
//
// Scans a folder for plaintext sensitive data that should not be sitting
// unencrypted on disk: credit card numbers (regex + Luhn check), private
// keys, cloud/API tokens (AWS/GitHub/Slack/Google), JWTs, DB connection
// strings with embedded credentials, and email:password leak-dump pairs.
//
// Detection-only (defensive). Double-click a row to reveal the file; the
// "Explain with AI" button jumps to the AI Assistant page with a prefilled
// prompt describing which kind of data leaked, so the assistant can advise
// on remediation. ASCII labels (MSVC builds without /utf-8).

#include "main_window.hpp"
#include "av_quit_guard.hpp"
#include "av_animations.hpp"
#include "hunt_toolbar.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QFileDialog>
#include <QHeaderView>
#include <QMessageBox>
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

struct DlpFinding {
    int         risk = 0;
    std::string type;
    std::string filename;
    std::string path;
    std::string detail;
};

struct DlpRule {
    const char* id;
    const char* cls;
    int         risk;
    const char* detail;
    QRegularExpression re;
};

QRegularExpression Mk(const char* pat) {
    return QRegularExpression(QString::fromUtf8(pat), QRegularExpression::CaseInsensitiveOption);
}

const std::vector<DlpRule>& Rules() {
    static const std::vector<DlpRule> rules = [] {
        std::vector<DlpRule> v;
        v.push_back({ "DLP-PRIVKEY", "Private key", 95,
            "Plaintext private key material (RSA/EC/OpenSSH/PGP)",
            Mk("-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----") });
        v.push_back({ "DLP-AWS-KEY", "AWS access key", 92,
            "AWS access key ID embedded in a file",
            Mk("AKIA[0-9A-Z]{16}") });
        v.push_back({ "DLP-GH-TOKEN", "GitHub token", 92,
            "GitHub personal access / OAuth token",
            Mk("gh[pousr]_[A-Za-z0-9]{36,}") });
        v.push_back({ "DLP-SLACK", "Slack token", 88,
            "Slack bot/user/app token",
            Mk("xox[baprs]-[A-Za-z0-9-]{10,}") });
        v.push_back({ "DLP-GOOGLE", "Google API key", 80,
            "Google Cloud API key",
            Mk("AIza[0-9A-Za-z_-]{35}") });
        v.push_back({ "DLP-JWT", "JWT token", 55,
            "JSON Web Token (may carry session/identity claims)",
            Mk("eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}") });
        v.push_back({ "DLP-DBCONN", "DB connection string", 85,
            "Database connection string with embedded username:password",
            Mk("(mongodb(\\+srv)?|postgres(ql)?|mysql|redis|amqp)://[^\\s:'\"]+:[^\\s@'\"]+@") });
        v.push_back({ "DLP-GENSECRET", "Hardcoded secret", 60,
            "Assignment of a secret/api key/password-like value",
            Mk("(api[_-]?key|secret|passwd|password|access[_-]?token)\\s*[:=]\\s*['\"][A-Za-z0-9/+_.-]{12,}['\"]") });
        v.push_back({ "DLP-CREDDUMP", "Credential leak-dump line", 90,
            "email:password (or user;pass) pair, the shape of a leaked-credential dump",
            Mk("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}[:;][^\\s:;]{4,}") });
        return v;
    }();
    return rules;
}

// Standalone 13-19 digit run, checked with Luhn before being reported as a card number.
const QRegularExpression& CardDigitsRe() {
    static const QRegularExpression re("(?:\\d[ -]?){13,19}");
    return re;
}

bool LuhnValid(const QString& digitsRun) {
    QString digits;
    digits.reserve(digitsRun.size());
    for (QChar c : digitsRun) if (c.isDigit()) digits += c;
    if (digits.size() < 13 || digits.size() > 19) return false;
    int sum = 0;
    bool dbl = false;
    for (int i = digits.size() - 1; i >= 0; --i) {
        int d = digits.at(i).digitValue();
        if (dbl) { d *= 2; if (d > 9) d -= 9; }
        sum += d;
        dbl = !dbl;
    }
    return sum % 10 == 0;
}

// Luhn alone isn't selective enough: any random 13-19 digit ID (article
// numbers, build numbers, telemetry IDs) has roughly a 1-in-10 chance of
// passing it by coincidence purely on math, causing false positives on
// large scans (e.g. an Adobe support-article-ID URL flagged as a "leaked
// card"). Real DLP tools also check the number against known issuer BIN
// (Bank Identification Number) prefix + length combos -- this is the
// standard second filter. A number that's Luhn-valid but doesn't match any
// real card brand's prefix+length is almost certainly not a card number.
bool LooksLikeRealCardBin(const QString& digitsRun) {
    QString d;
    d.reserve(digitsRun.size());
    for (QChar c : digitsRun) if (c.isDigit()) d += c;
    const int n = d.size();

    auto starts = [&](const char* prefix) { return d.startsWith(QString::fromLatin1(prefix)); };
    auto startsRange = [&](int lo, int hi, int digits) {
        if (d.size() < digits) return false;
        bool ok = d.left(digits).toInt() >= lo && d.left(digits).toInt() <= hi;
        return ok;
    };

    if (starts("4") && (n == 13 || n == 16 || n == 19)) return true;                 // Visa
    if (startsRange(51, 55, 2) && n == 16) return true;                              // Mastercard (51-55)
    if (startsRange(2221, 2720, 4) && n == 16) return true;                          // Mastercard (2221-2720)
    if ((starts("34") || starts("37")) && n == 15) return true;                      // Amex
    if (starts("6011") && n == 16) return true;                                      // Discover
    if (startsRange(644, 649, 3) && n == 16) return true;                            // Discover
    if (starts("65") && n == 16) return true;                                        // Discover
    if (startsRange(300, 305, 3) && n == 14) return true;                            // Diners Club
    if ((starts("36") || starts("38")) && n == 14) return true;                      // Diners Club
    if (startsRange(3528, 3589, 4) && n == 16) return true;                          // JCB
    if (starts("62") && (n >= 16 && n <= 19)) return true;                           // UnionPay
    return false;
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

// Vendor/OS-shipped directory trees are the dominant false-positive source:
// they're full of numeric IDs (build numbers, article IDs, telemetry) that
// coincidentally look card-like, and they're not the user's own data anyway
// -- a real leak from this specific user lives in their own documents, dev
// projects, or an app's OWN config (which is why %AppData%/ProgramData are
// deliberately NOT excluded here -- e.g. an FTP client's saved-password file
// is exactly the kind of real leak DLP should still catch there). Pruned as
// whole subtrees (not per-file) so the scan also skips descending into them
// entirely -- faster on top of being more accurate.
bool IsVendorOrSystemDir(const fs::path& p) {
    std::wstring w = p.filename().wstring();
    for (auto& c : w) c = towlower(c);
    static const wchar_t* kSkipDirs[] = {
        L"windows", L"program files", L"program files (x86)",
        L"node_modules", L".git", L"$recycle.bin", L"winsxs", nullptr
    };
    for (int i = 0; kSkipDirs[i]; ++i) if (w == kSkipDirs[i]) return true;
    return false;
}

// Only inspect plaintext-ish files to stay fast and avoid binary noise.
bool ShouldInspect(const fs::path& p) {
    const std::string ext = LowerExt(p);
    static const char* exts[] = { "txt","json","js","ts","py","env","yml","yaml","toml","ini","cfg",
                                  "conf","xml","csv","log","sql","ps1","sh","bat","cmd","pem","key",
                                  "config","properties", nullptr };
    for (int i = 0; exts[i]; ++i) if (ext == exts[i]) return true;
    const std::string name = p.filename().string();
    return name == ".env" || name == "id_rsa" || name == "credentials" || name == ".npmrc";
}

QString ReadTextCapped(const fs::path& p, qint64 cap = 512 * 1024) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    std::string buf(static_cast<size_t>(cap), '\0');
    f.read(buf.data(), cap);
    buf.resize(static_cast<size_t>(f.gcount()));
    return QString::fromUtf8(buf.c_str(), static_cast<int>(buf.size()));
}

void AnalyzeFile(const fs::path& p, std::vector<DlpFinding>& out) {
    if (!ShouldInspect(p)) return;
    const QString content = ReadTextCapped(p);
    if (content.isEmpty()) return;
    const std::string fname = Utf8(p.filename().wstring());
    const std::string spath = Utf8(p.wstring());

    for (const auto& rule : Rules()) {
        if (rule.re.match(content).hasMatch()) {
            out.push_back({ rule.risk, rule.cls, fname, spath, rule.detail });
        }
    }

    // Card numbers need Luhn AND a real issuer BIN-prefix+length match to cut
    // false positives. Luhn alone flags ~1-in-10 random digit runs (article
    // IDs, build numbers, telemetry IDs) -- confirmed live on this machine:
    // an Adobe After Effects system file (blocklist.en_US.json) was flagged
    // because a Zendesk support-article-ID embedded in a URL happened to
    // pass Luhn. Requiring a plausible brand prefix+length combo on top
    // eliminates that whole class of false positive.

    // Additional context filter: skip card detection in dependency files (package.json, lock files)
    // These files are full of numeric version IDs, build hashes that coincidentally pass Luhn.
    const bool isDependencyFile = (fname.find("package.json") != std::string::npos ||
                                   fname.find("package-lock.json") != std::string::npos ||
                                   fname.find(".lock") != std::string::npos ||
                                   fname.find("Gemfile.lock") != std::string::npos ||
                                   fname.find("Cargo.lock") != std::string::npos);

    if (!isDependencyFile) {
        auto it = CardDigitsRe().globalMatch(content);
        bool cardFound = false;
        while (it.hasNext() && !cardFound) {
            const auto m = it.next();
            const QString match = m.captured(0);
            if (LuhnValid(match) && LooksLikeRealCardBin(match)) cardFound = true;
        }
        if (cardFound) {
            out.push_back({ 90, "Credit card number", fname, spath,
                "Luhn-valid card number matching a real issuer prefix found in plaintext" });
        }
    }
}

QColor RiskColor(int r) {
    if (r >= 85) return QColor(0xFF, 0x3B, 0x50);
    if (r >= 55) return QColor(0xFF, 0x7A, 0x00);
    return QColor(0xE6, 0xC2, 0x4A);
}

} // namespace

QWidget* BuildDlpPage(QWidget* parent) {
    auto* win = qobject_cast<MainWindow*>(parent);
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(12);

    auto* title = new QLabel(QString::fromUtf8("Data Loss Prevention"), page);
    title->setStyleSheet("color:#E8E8E8; font-size:16pt; font-weight:800; background:transparent;");
    root->addWidget(title);
    auto* sub = new QLabel(QString::fromUtf8(
        "Scans a folder for plaintext sensitive data at rest: credit card numbers "
        "(Luhn-verified), private keys, cloud/API tokens (AWS/GitHub/Slack/Google), JWTs, "
        "database connection strings with embedded credentials, and email:password leak-dump lines."), page);
    sub->setStyleSheet("color:#8B8B8B; font-size:9pt; background:transparent;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(12);
    auto* scan_btn = new QPushButton(QString::fromUtf8("Choose folder & scan"), page);
    scan_btn->setCursor(Qt::PointingHandCursor);
    scan_btn->setStyleSheet(
        "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #CC5500);"
        " border:none; border-radius:10px; color:#fff; font-size:10.5pt; font-weight:700; padding:10px 24px; }"
        "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9030,stop:1 #DD6600); }"
        "QPushButton:disabled { background:#2A1F14; color:#8B8B8B; }");
    ctl->addWidget(scan_btn);

    auto* ai_btn = new QPushButton(QString::fromUtf8("Explain with AI"), page);
    ai_btn->setCursor(Qt::PointingHandCursor);
    ai_btn->setEnabled(false);
    ai_btn->setStyleSheet(
        "QPushButton { background:#1C1008; border:1px solid rgba(255,122,0,60); border-radius:10px;"
        " color:#FF9030; font-size:10pt; font-weight:600; padding:10px 20px; }"
        "QPushButton:hover:enabled { background:#2A1F14; }"
        "QPushButton:disabled { color:#5A5A5A; border-color:rgba(139,139,139,40); }");
    ctl->addWidget(ai_btn);

    auto* status = new QLabel(QString::fromUtf8("Idle. Pick a folder to scan for exposed secrets/PII."), page);
    status->setStyleSheet("color:#C8B8A8; font-size:9.5pt; background:transparent;");
    ctl->addWidget(status, 1);
    root->addLayout(ctl);

    auto* table = new QTableWidget(0, 4, page);
    table->setHorizontalHeaderLabels({"Risk", "Type", "File", "Detail"});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);
    table->setStyleSheet(
        theme::TableQss());
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

    QObject::connect(table, &QTableWidget::itemSelectionChanged, table, [table, ai_btn]() {
        ai_btn->setEnabled(!table->selectedItems().isEmpty());
    });

    QObject::connect(ai_btn, &QPushButton::clicked, table, [table, win]() {
        const int row = table->currentRow();
        if (row < 0 || !win) {
            if (!win) QMessageBox::warning(nullptr, "AI Assistant",
                QString::fromUtf8("AI Assistant not available. Make sure it's initialized."));
            return;
        }
        auto* typeIt = table->item(row, 1);
        auto* fileIt = table->item(row, 2);
        auto* detIt  = table->item(row, 3);
        if (!typeIt || !fileIt || !detIt) return; // Safety check on items
        const QString prompt = QString::fromUtf8(
            "A DLP scan found a potential data leak: type=\"%1\", file=\"%2\", detail=\"%3\". "
            "Explain the risk and how I should remediate it (rotate secret, encrypt file, add to .gitignore, etc).")
            .arg(typeIt->text())
            .arg(fileIt->text())
            .arg(detIt->text());
        win->OpenAiWithPrompt(prompt);
    });

    ArmQuitGuard(page);
    auto scanning = std::make_shared<std::atomic<bool>>(false);
    auto scanned  = std::make_shared<std::atomic<long long>>(0);
    auto flagged  = std::make_shared<std::atomic<long long>>(0);

    auto addRow = [table](const DlpFinding& f) {
        const int row = table->rowCount();
        table->insertRow(row);
        auto* risk = new QTableWidgetItem(QString::number(f.risk));
        risk->setForeground(RiskColor(f.risk));

        // Background color by risk
        QString bg;
        if (f.risk >= 90) bg = "#3A1F1F";
        else if (f.risk >= 70) bg = "#3A2F1F";
        else if (f.risk >= 50) bg = "#2F3A1F";
        else bg = "#1F2F1F";

        table->setItem(row, 0, risk);
        auto* type = new QTableWidgetItem(QString::fromStdString(f.type));
        type->setForeground(RiskColor(f.risk));
        type->setBackground(QColor(bg));
        table->setItem(row, 1, type);
        auto* file = new QTableWidgetItem(QString::fromStdString(f.filename));
        file->setData(Qt::UserRole, QString::fromStdString(f.path));
        file->setToolTip(QString::fromStdString(f.path));
        file->setBackground(QColor(bg));
        table->setItem(row, 2, file);
        auto* detail = new QTableWidgetItem(QString::fromStdString(f.detail));
        detail->setBackground(QColor(bg));
        table->setItem(row, 3, detail);
    };

    QObject::connect(scan_btn, &QPushButton::clicked, page,
            [page, scan_btn, status, table, scanning, scanned, flagged, addRow]() {
        if (scanning->load()) return;
        const QString dir = QFileDialog::getExistingDirectory(
            page, QString::fromUtf8("Choose folder to scan for leaked data"), QString(),
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
                if (it->is_directory(fec) && IsVendorOrSystemDir(it->path())) {
                    it.disable_recursion_pending(); // prune the whole subtree
                    continue;
                }
                if (!it->is_regular_file(fec) || fec) continue;
                scanned->fetch_add(1);
                std::vector<DlpFinding> found;
                try { AnalyzeFile(it->path(), found); } catch (...) {}
                for (auto& f : found) {
                    flagged->fetch_add(1);
                    // Capture f by value (copy) to avoid use-after-free when lambda
                    // runs on GUI thread after f goes out of scope.
                    auto f_copy = f;
                    QMetaObject::invokeMethod(table, [addRow, f_copy]() { addRow(f_copy); }, Qt::QueuedConnection);
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

    auto* export_btn = MakeExportButton(page, table, QString::fromUtf8("dlp_findings.csv"));
    ctl->addWidget(export_btn);

    auto* sync = new QTimer(page);
    sync->setInterval(300);
    QObject::connect(sync, &QTimer::timeout, scan_btn,
        [scan_btn, export_btn, table, scanning]() {
        const bool idle = !scanning->load();
        scan_btn->setEnabled(idle);
        export_btn->setEnabled(idle && table->rowCount() > 0);
    });
    sync->start();

    return page;
}

} // namespace avdashboard
