// main_window_waf.cpp — Web Application Firewall (WAF): multi-layer rule engine + tester.
//
// Three layers, evaluated together with OWASP-CRS-style anomaly scoring:
//   Layer 1  Protocol / anomaly   (null bytes, encoded traversal, CRLF, double-encoding)
//   Layer 2  Attack signatures    (SQLi, XSS, LFI/traversal, RCE/cmdi, SSRF, XXE, scanners)
//   Layer 3  Anomaly scoring      (sum of matched severities → ALLOW / SUSPICIOUS / BLOCK)
//
// This is a request inspector/tester: paste a raw HTTP request and it reports which
// rules fired, in which layer, the attack class, and the final verdict. Labels are
// ASCII on purpose (MSVC builds this without /utf-8).

#include "main_window.hpp"
#include "theme.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QWidget>

#include <vector>

namespace avdashboard {
namespace {

enum class Sev { Low, Medium, High, Critical };

int SevWeight(Sev s) {
    switch (s) {
        case Sev::Critical: return 5;
        case Sev::High:     return 3;
        case Sev::Medium:   return 2;
        default:            return 1;
    }
}
const char* SevName(Sev s) {
    switch (s) {
        case Sev::Critical: return "CRITICAL";
        case Sev::High:     return "HIGH";
        case Sev::Medium:   return "MEDIUM";
        default:            return "LOW";
    }
}
QColor SevColor(Sev s) {
    switch (s) {
        case Sev::Critical: return QColor(0xFF, 0x3B, 0x50);
        case Sev::High:     return QColor(0xFF, 0x5A, 0x6A);
        case Sev::Medium:   return QColor(0xFF, 0x7A, 0x00);
        default:            return QColor(0xE6, 0xC2, 0x4A);
    }
}

struct WafRule {
    QString id;
    int     layer;      // 1, 2, or 3
    QString cls;        // attack class
    Sev     sev;
    QString desc;
    QRegularExpression re;
};

const std::vector<WafRule>& Rules() {
    static const std::vector<WafRule> rules = [] {
        auto R = [](const char* id, int layer, const char* cls, Sev sev,
                    const char* desc, const char* pat) {
            return WafRule{ id, layer, cls, sev, desc,
                QRegularExpression(QString::fromUtf8(pat),
                                   QRegularExpression::CaseInsensitiveOption) };
        };
        std::vector<WafRule> v;

        // ── Layer 1 — Protocol / anomaly ──────────────────────────────────
        v.push_back(R("WAF-PROTO-001", 1, "Protocol", Sev::Medium,
            "Null byte in request", "%00|\\x00"));
        v.push_back(R("WAF-PROTO-002", 1, "Protocol", Sev::High,
            "Encoded path traversal", "\\.\\./|\\.\\.\\\\|%2e%2e|%252e"));
        v.push_back(R("WAF-PROTO-003", 1, "Protocol", Sev::Medium,
            "Double URL-encoding", "%25(2f|5c|2e|00)"));
        v.push_back(R("WAF-PROTO-004", 1, "Protocol", Sev::Medium,
            "CRLF / header injection", "%0d%0a|%0a|%0d|\\r\\n"));

        // ── Layer 2 — Attack signatures ───────────────────────────────────
        // SQL injection
        v.push_back(R("WAF-SQLI-001", 2, "SQLi", Sev::Critical,
            "SQL tautology (OR/AND 1=1)", "('|%27|\\s)(or|and)\\s+\\d+\\s*=\\s*\\d+"));
        v.push_back(R("WAF-SQLI-002", 2, "SQLi", Sev::Critical,
            "UNION SELECT", "union[\\s/*]+select"));
        v.push_back(R("WAF-SQLI-003", 2, "SQLi", Sev::High,
            "SELECT ... FROM", "select\\s+.+\\s+from\\s+"));
        v.push_back(R("WAF-SQLI-004", 2, "SQLi", Sev::Critical,
            "Stacked DROP/DELETE", ";\\s*(drop|delete|truncate)\\s+"));
        v.push_back(R("WAF-SQLI-005", 2, "SQLi", Sev::High,
            "Time-based blind (sleep/benchmark)", "(sleep|benchmark|pg_sleep|waitfor\\s+delay)\\s*\\("));
        v.push_back(R("WAF-SQLI-006", 2, "SQLi", Sev::High,
            "Schema probing / stacked comment", "information_schema|xp_cmdshell|--\\s|/\\*!"));

        // Cross-site scripting
        v.push_back(R("WAF-XSS-001", 2, "XSS", Sev::Critical,
            "Script tag", "<\\s*script"));
        v.push_back(R("WAF-XSS-002", 2, "XSS", Sev::High,
            "javascript: URI", "javascript:"));
        v.push_back(R("WAF-XSS-003", 2, "XSS", Sev::High,
            "Inline event handler", "on(error|load|click|mouseover)\\s*="));
        v.push_back(R("WAF-XSS-004", 2, "XSS", Sev::High,
            "DOM / cookie theft", "document\\.(cookie|location)|<\\s*svg|alert\\s*\\("));

        // Path traversal / LFI
        v.push_back(R("WAF-LFI-001", 2, "LFI/Traversal", Sev::Critical,
            "Sensitive file access", "/etc/passwd|/etc/shadow|boot\\.ini|win\\.ini"));
        v.push_back(R("WAF-LFI-002", 2, "LFI/Traversal", Sev::High,
            "PHP / file wrapper", "php://|file://|zip://|expect://"));

        // Remote code / command injection
        v.push_back(R("WAF-RCE-001", 2, "RCE/CmdInj", Sev::Critical,
            "Shell command chaining", "(;|\\||&&|\\$\\(|`)\\s*(cat|ls|id|whoami|uname|nc|curl|wget|bash|sh|powershell|cmd)\\b"));
        v.push_back(R("WAF-RCE-002", 2, "RCE/CmdInj", Sev::High,
            "Pipe to netcat / reverse shell", "\\|\\s*nc\\b|/dev/tcp/|bash\\s+-i"));

        // SSRF
        v.push_back(R("WAF-SSRF-001", 2, "SSRF", Sev::High,
            "Internal / metadata target", "https?://(127\\.0\\.0\\.1|localhost|169\\.254\\.169\\.254|0\\.0\\.0\\.0|\\[::1\\])"));

        // XXE
        v.push_back(R("WAF-XXE-001", 2, "XXE", Sev::Critical,
            "External entity", "<!ENTITY|<!DOCTYPE[^>]+SYSTEM|SYSTEM\\s+\"file:"));

        // Scanners / offensive tools (matched on User-Agent or anywhere)
        v.push_back(R("WAF-SCAN-001", 2, "Scanner", Sev::Medium,
            "Known scanner / attack tool", "sqlmap|nikto|nmap|acunetix|nessus|dirbuster|gobuster|wpscan|masscan|hydra|havij"));

        return v;
    }();
    return rules;
}

struct WafMatch { const WafRule* rule; QString sample; };
struct WafResult { std::vector<WafMatch> matches; int score = 0; QString verdict; };

WafResult Evaluate(const QString& request) {
    WafResult res;
    for (const auto& rule : Rules()) {
        const auto m = rule.re.match(request);
        if (m.hasMatch()) {
            res.matches.push_back({ &rule, m.captured(0) });
            res.score += SevWeight(rule.sev);
        }
    }
    // OWASP-CRS-style anomaly threshold.
    res.verdict = res.score >= 5 ? "BLOCK" : (res.score > 0 ? "SUSPICIOUS" : "ALLOW");
    return res;
}

} // namespace

QWidget* BuildWafPage(QWidget* parent) {
    (void)parent;
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(12);

    auto* title = new QLabel(QString::fromUtf8("Web Application Firewall (WAF)"), page);
    title->setStyleSheet("color:#ECE4DA; font-size:28px; font-weight:700; background:transparent;");
    root->addWidget(title);

    int l1 = 0, l2 = 0;
    for (const auto& r : Rules()) { if (r.layer == 1) ++l1; else if (r.layer == 2) ++l2; }
    auto* sub = new QLabel(QString::fromUtf8(
        "Multi-layer engine: Layer 1 protocol/anomaly (%1) -> Layer 2 attack signatures (%2) "
        "-> Layer 3 anomaly scoring. %3 rules loaded.")
        .arg(l1).arg(l2).arg(static_cast<int>(Rules().size())), page);
    sub->setStyleSheet("color:#8B7355; font-size:9pt; background:transparent;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    // Request input
    auto* input = new QPlainTextEdit(page);
    input->setStyleSheet(
        "QPlainTextEdit { background:#1C1108; color:#ECE4DA; border:1px solid rgba(255,170,90,26);"
        " border-radius:10px; padding:8px; font-family:Consolas,monospace; font-size:10pt; }");
    input->setPlaceholderText(QString::fromUtf8("Paste a raw HTTP request (path, query, headers, body)..."));
    input->setPlainText(QString::fromUtf8(
        "GET /products?id=1' OR 1=1-- UNION SELECT username,password FROM users HTTP/1.1\n"
        "Host: shop.example.com\n"
        "User-Agent: sqlmap/1.5.2\n"
        "X-Note: <script>alert(document.cookie)</script>\n"
        "\n"
        "path=../../../../etc/passwd; cat /etc/shadow"));
    input->setFixedHeight(150);
    root->addWidget(input);

    // Control + verdict row
    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(12);
    auto* eval_btn = new QPushButton(QString::fromUtf8("Evaluate request"), page);
    eval_btn->setCursor(Qt::PointingHandCursor);
    eval_btn->setStyleSheet(
        "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #CC5500);"
        " border:none; border-radius:10px; color:#fff; font-size:10.5pt; font-weight:700; padding:9px 24px; }"
        "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9030,stop:1 #DD6600); }");
    ctl->addWidget(eval_btn);
    auto* verdict = new QLabel(page);
    verdict->setAlignment(Qt::AlignCenter);
    verdict->setFixedHeight(34);
    verdict->setMinimumWidth(180);
    ctl->addWidget(verdict);
    auto* score_lbl = new QLabel(page);
    score_lbl->setStyleSheet("color:#C7B6A2; font-size:10pt; background:transparent;");
    ctl->addWidget(score_lbl);
    ctl->addStretch();
    root->addLayout(ctl);

    // Matched-rules table
    auto* table = new QTableWidget(0, 5, page);
    table->setHorizontalHeaderLabels({"Rule ID", "Layer", "Class", "Severity", "Matched"});
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
        h->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        h->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    }
    root->addWidget(table, 1);

    auto runEval = [table, verdict, score_lbl, input] {
        const WafResult res = Evaluate(input->toPlainText());
        table->setRowCount(0);
        for (const auto& m : res.matches) {
            const int row = table->rowCount();
            table->insertRow(row);
            table->setItem(row, 0, new QTableWidgetItem(m.rule->id));
            table->setItem(row, 1, new QTableWidgetItem(QString::number(m.rule->layer)));
            table->setItem(row, 2, new QTableWidgetItem(m.rule->cls));
            auto* sev = new QTableWidgetItem(QString::fromUtf8(SevName(m.rule->sev)));
            sev->setForeground(SevColor(m.rule->sev));
            table->setItem(row, 3, sev);
            auto* matched = new QTableWidgetItem(m.sample.trimmed().left(80));
            matched->setToolTip(m.rule->desc);
            table->setItem(row, 4, matched);
        }
        score_lbl->setText(QString::fromUtf8("Anomaly score: %1  (block threshold 5)").arg(res.score));

        QString bg = "#4ADE80", fg = "#0B2015", txt = "ALLOW";
        if (res.verdict == "BLOCK")      { bg = "#FF3B50"; fg = "#fff"; txt = "BLOCK"; }
        else if (res.verdict == "SUSPICIOUS") { bg = "#FF7A00"; fg = "#fff"; txt = "SUSPICIOUS"; }
        verdict->setText(txt + QString::fromUtf8("  (%1 rules)").arg(static_cast<int>(res.matches.size())));
        verdict->setStyleSheet(QString(
            "background:%1; color:%2; border-radius:8px; font-size:11pt; font-weight:800;"
            " padding:6px 14px;").arg(bg, fg));
    };

    QObject::connect(eval_btn, &QPushButton::clicked, page, runEval);
    QObject::connect(input, &QPlainTextEdit::textChanged, page, runEval);
    runEval(); // auto-evaluate the sample so results are visible immediately

    return page;
}

} // namespace avdashboard
