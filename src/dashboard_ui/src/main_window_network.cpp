// main_window_network.cpp — Zero-Trust C2 Network Monitor (page 7)
// Replaces the basic netstat-only implementation with risk scoring,
// CDN detection, DGA entropy analysis, and per-process LOLBin flagging.

#include "main_window.hpp"
#include "av_quit_guard.hpp"
#include "avengine/engine.hpp"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <algorithm>
#include <cmath>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <tlhelp32.h>

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPainter>
#include <QPainterPath>
#include <QProcess>
#include <QPushButton>
#include <QScrollArea>
#include <QSizePolicy>
#include <QSpinBox>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

namespace avdashboard {

// ─── C2 Risk Scoring helpers ──────────────────────────────────────────────────
namespace {

// Known LOLBins — any outbound connection is elevated risk
static const std::unordered_set<std::string> kLolBins = {
    "powershell.exe", "powershell_ise.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
    "msiexec.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "cmstp.exe", "pcalua.exe", "wmic.exe", "xwizard.exe",
    "presentationhost.exe", "ieexec.exe", "msdeploy.exe",
    "infdefaultinstall.exe", "control.exe",
};

// Ports that don't add extra risk
static const std::unordered_set<int> kStdPorts = {
    53, 80, 443, 465, 587, 636, 993, 995, 8080, 8443,
    21, 22, 25, 110, 143, 3389,
};

// Suspicious TLDs often used for C2 / phishing
static const std::unordered_set<std::string> kSusTlds = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu",
    "bid", "click", "link", "cam", "monster", "cyou",
    "vip", "work", "rest", "bar",
};

// Keywords in hostname → likely C2 panel / beacon
static const std::vector<std::string> kC2Keywords = {
    "beacon", "c2.", ".c2", "panel.", "payload", "dropper",
    "gate.", "loader", "stager", "implant", "agent.",
    "cnc", "command", "control",
};

// IP CIDR range entry — used for CDN and Microsoft IP classification
struct CidrEntry { uint32_t net_be; uint32_t mask; const char* name; };

// Known Windows system processes — reduced scrutiny when on std ports + MS IPs
static const std::unordered_set<std::string> kSysProcs = {
    "system", "svchost.exe", "lsass.exe", "services.exe", "winlogon.exe",
    "csrss.exe", "wininit.exe", "smss.exe", "spoolsv.exe", "dwm.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe", "ctfmon.exe",
    "runtimebroker.exe", "searchhost.exe", "searchindexer.exe",
    "securityhealthservice.exe", "msmpeng.exe", "nissrv.exe",
    "mssense.exe", "audiodg.exe", "wudfhost.exe", "wmiprvse.exe",
    "tabtip.exe", "explorer.exe",
};

// Known Microsoft/Windows Update IP ranges — system processes on these = low risk
static const CidrEntry kMsftRanges[] = {
    {0x0D000000u, 0xFF000000u, "Microsoft"}, // 13.x.x.x
    {0x28000000u, 0xFF000000u, "Microsoft"}, // 40.x.x.x
    {0x34000000u, 0xFF000000u, "Microsoft"}, // 52.x.x.x
    {0x41000000u, 0xFF000000u, "Microsoft"}, // 65.x.x.x
    {0x4A000000u, 0xFF000000u, "Microsoft"}, // 74.x.x.x
    {0x68000000u, 0xFF000000u, "Microsoft"}, // 104.x.x.x
    {0xCF000000u, 0xFF000000u, "Microsoft"}, // 207.x.x.x
    {0xD8000000u, 0xFF000000u, "Microsoft"}, // 216.x.x.x
};

static bool IsMicrosoftIp(uint32_t ip_h) {
    for (const auto& r : kMsftRanges)
        if ((ip_h & r.mask) == (ntohl(r.net_be) & r.mask)) return true;
    return false;
}

// Cache TTL by risk tier (seconds)
static int64_t CacheTtl(int score) {
    if (score >= 70) return 8;   // high risk: re-score every ~10s
    if (score >= 35) return 25;  // medium:   re-score every ~30s
    return 90;                   // low:      re-score every ~2min
}

// CDN ranges for zero-trust flagging
static const CidrEntry kCdnRanges[] = {
    // Cloudflare
    {0x01010100u, 0xFFFFFF00u, "Cloudflare"},   // 1.1.1.0/24
    {0x01000000u, 0xFFFFFF00u, "Cloudflare"},   // 1.0.0.0/24
    {0x68100000u, 0xFFF00000u, "Cloudflare"},   // 104.16.0.0/12
    {0x68180000u, 0xFFFC0000u, "Cloudflare"},   // 104.24.0.0/14
    {0xAC400000u, 0xFFF80000u, "Cloudflare"},   // 172.64.0.0/13
    {0xBC726000u, 0xFFFFF000u, "Cloudflare"},   // 188.114.96.0/20
    {0xBE5DF000u, 0xFFFFF000u, "Cloudflare"},   // 190.93.240.0/20
    {0xC5EAF000u, 0xFFFFFC00u, "Cloudflare"},   // 197.234.240.0/22
    {0xC6298000u, 0xFFFF8000u, "Cloudflare"},   // 198.41.128.0/17
    // AWS CloudFront
    {0x0D200000u, 0xFFFE0000u, "AWS CF"},       // 13.32.0.0/15
    {0x0D230000u, 0xFFFF0000u, "AWS CF"},       // 13.35.0.0/16
    {0x34540000u, 0xFFFE0000u, "AWS CF"},       // 52.84.0.0/15
    {0x63540000u, 0xFFFF0000u, "AWS CF"},       // 99.84.0.0/16
    {0x40400000u, 0xFFFFC000u, "AWS CF"},       // 64.64.0.0/18 approx
    // Azure CDN
    {0x0D400000u, 0xFFE00000u, "Azure CDN"},    // 13.64.0.0/11
    {0x17600000u, 0xFFF80000u, "Azure CDN"},    // 23.96.0.0/13
    {0x28400000u, 0xFFC00000u, "Azure CDN"},    // 40.64.0.0/10
    // Fastly
    {0x17EB2000u, 0xFFFFE000u, "Fastly"},       // 23.235.32.0/20
    {0x97650000u, 0xFFFF0000u, "Fastly"},       // 151.101.0.0/16
    // Akamai (sample)
    {0x17000000u, 0xFF000000u, "Akamai"},       // 23.0.0.0/8 subset
    // Google
    {0x42660000u, 0xFFFF0000u, "Google"},       // 66.102.0.0/16
    {0x4A7D2000u, 0xFFFF0000u, "Google"},       // 74.125.0.0/16
    {0x8EFA0000u, 0xFFFF0000u, "Google"},       // 142.250.0.0/16
    {0x8EFB0000u, 0xFFFF0000u, "Google"},       // 142.251.0.0/16
};

// Convert dotted IPv4 string to big-endian uint32
static uint32_t ParseIpBe(const std::string& ip) {
    in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return 0;
    return ntohl(a.s_addr);  // host byte order for comparison
}

// Returns CDN name or "" if not in any known range
static std::string CheckCdn(uint32_t ip_host) {
    for (const auto& r : kCdnRanges)
        if ((ip_host & r.mask) == (ntohl(r.net_be) & r.mask))
            return r.name;
    return "";
}

// Is address private/loopback?
static bool IsPrivateIp(uint32_t ip) {
    return (ip >> 24) == 10
        || (ip >> 16) == 0xAC10  // 172.16-31.x.x
        || (ip >> 24) == 192 && ((ip >> 16) & 0xFF) == 168
        || (ip >> 24) == 127
        || (ip >> 24) == 0;
}

// Shannon entropy of a string (for DGA detection)
static double Entropy(const std::string& s) {
    if (s.size() < 4) return 0.0;
    int freq[256] = {};
    for (unsigned char c : s) ++freq[c];
    double e = 0.0;
    for (int f : freq) {
        if (f == 0) continue;
        double p = (double)f / s.size();
        e -= p * std::log2(p);
    }
    return e;
}

// Extract registrable domain from hostname (e.g. "sub.evil.tk" → "evil.tk")
static std::string BaseDomain(const std::string& host) {
    const auto last = host.rfind('.');
    if (last == std::string::npos) return host;
    const auto prev = host.rfind('.', last - 1);
    if (prev == std::string::npos) return host;
    return host.substr(prev + 1);
}

struct RiskResult {
    int   score;      // 0-100
    std::string label;   // comma-separated reasons
    std::string cdn;     // "Cloudflare", "AWS CF", … or ""
};

static RiskResult ScoreConn(
    const std::string& proc_lower,
    const std::string& remote_ip,
    const std::string& hostname,   // resolved hostname or ""
    int remote_port,
    bool established)
{
    int score = 0;
    std::vector<std::string> reasons;
    std::string cdn;

    const uint32_t ip_h = ParseIpBe(remote_ip);
    const bool priv = IsPrivateIp(ip_h);

    // Don't score loopback / private connections
    if (priv || ip_h == 0) return {0, "", ""};

    const bool is_sys_proc  = kSysProcs.count(proc_lower) > 0;
    const bool is_msft_ip   = IsMicrosoftIp(ip_h);
    const bool is_std_port  = kStdPorts.count(remote_port) > 0;

    // System process + Microsoft IP + standard port = baseline safe (zero-trust note only)
    if (is_sys_proc && is_msft_ip && is_std_port) {
        return {0, "SysProc+MSFT", ""};
    }
    // System process + Microsoft IP + non-standard port = mildly suspicious
    if (is_sys_proc && is_msft_ip) {
        return {8, "SysProc+MSFT NonStdPort", ""};
    }

    // CDN check
    cdn = CheckCdn(ip_h);

    // LOLBin
    if (kLolBins.count(proc_lower)) {
        score += 40;
        reasons.push_back("LOLBin");
        if (!cdn.empty()) { score += 20; reasons.push_back(cdn + " Fronting?"); }
    } else if (!cdn.empty()) {
        // Zero-trust: CDN flagged at low level unless from system proc
        if (!is_sys_proc) { score += 8; reasons.push_back("via " + cdn); }
    }

    // System process making unexpected connection (not to Microsoft, not std port)
    if (is_sys_proc && !is_msft_ip && !is_std_port) {
        score += 25;
        reasons.push_back("SysProc Anomaly");
    }

    // Non-standard port (skip for known sys procs on CDN — already flagged above)
    if (remote_port > 0 && !is_std_port && !is_sys_proc) {
        score += 15;
        reasons.push_back("Non-Std Port");
    }

    // svchost on non-standard port
    if (proc_lower == "svchost.exe" && remote_port > 0 && !kStdPorts.count(remote_port)) {
        score += 20;
        reasons.push_back("svchost Anomaly");
    }

    // Hostname-based analysis
    const std::string& target = hostname.empty() ? "" : hostname;
    if (!target.empty()) {
        const std::string base = BaseDomain(target);

        // TLD suspicion
        const auto dot = base.rfind('.');
        if (dot != std::string::npos) {
            std::string tld = base.substr(dot + 1);
            std::transform(tld.begin(), tld.end(), tld.begin(), ::tolower);
            if (kSusTlds.count(tld)) { score += 20; reasons.push_back("Sus TLD"); }
        }

        // DGA entropy on SLD portion
        const std::string sld = (dot != std::string::npos) ? base.substr(0, dot) : base;
        const double ent = Entropy(sld);
        if (ent > 4.0)      { score += 40; reasons.push_back("DGA (ent=" + std::to_string((int)(ent*10)/10.0).substr(0,3) + ")"); }
        else if (ent > 3.3) { score += 20; reasons.push_back("DGA-Like"); }

        // C2 keywords in hostname
        std::string host_lower = target;
        std::transform(host_lower.begin(), host_lower.end(), host_lower.begin(), ::tolower);
        for (const auto& kw : kC2Keywords)
            if (host_lower.find(kw) != std::string::npos) {
                score += 25;
                reasons.push_back("C2 Pattern");
                break;
            }
    } else if (!priv && cdn.empty()) {
        // Direct IP connection to unknown external host
        score += 8;
        reasons.push_back("Direct IP");
    }

    // Bonus: not established — reduce weight slightly
    if (!established) score = score * 7 / 10;

    score = std::min(score, 100);
    std::string label;
    for (size_t i = 0; i < reasons.size(); ++i) {
        if (i) label += " + ";
        label += reasons[i];
    }
    return {score, label, cdn};
}

// ─── Risk badge widget ────────────────────────────────────────────────────────
// Small colored pill showing the risk score
class RiskBadge : public QWidget {
public:
    explicit RiskBadge(int score, QWidget* parent = nullptr)
        : QWidget(parent), score_(score) {
        setFixedSize(42, 20);
    }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        QColor bg;
        if      (score_ >= 70) bg = QColor(0xFF, 0x3A, 0x3A, 200);
        else if (score_ >= 35) bg = QColor(0xFF, 0x7A, 0x00, 200);
        else                   bg = QColor(0x1F, 0xA8, 0x55, 200);
        p.setPen(Qt::NoPen);
        p.setBrush(bg);
        p.drawRoundedRect(rect(), 4, 4);
        p.setPen(Qt::white);
        QFont f = p.font(); f.setPointSizeF(7.5); f.setBold(true); p.setFont(f);
        p.drawText(rect(), Qt::AlignCenter, QString::number(score_));
    }
private:
    int score_;
};

// ─── NavIcon for network page header ─────────────────────────────────────────
class NetIcon : public QWidget {
public:
    enum Type { Shield, Globe, Filter, Refresh, Search };
    NetIcon(Type t, int sz, QColor col, QWidget* p = nullptr)
        : QWidget(p), t_(t), sz_(sz), col_(col) {
        setFixedSize(sz, sz);
    }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter pa(this);
        pa.setRenderHint(QPainter::Antialiasing);
        const double s = sz_ / 24.0;
        QPen pen(col_, 1.7 * s, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
        pa.setPen(pen);
        pa.setBrush(Qt::NoBrush);
        switch (t_) {
        case Shield: {
            QPainterPath pp;
            pp.moveTo(12*s, 2*s);
            pp.lineTo(20*s, 6*s); pp.lineTo(20*s, 12*s);
            pp.cubicTo(20*s,17*s, 16*s,20.5*s, 12*s,22*s);
            pp.cubicTo(8*s,20.5*s, 4*s,17*s, 4*s,12*s);
            pp.lineTo(4*s, 6*s); pp.closeSubpath();
            pa.drawPath(pp);
            pa.drawLine(QPointF(12*s,8*s), QPointF(12*s,15*s));
            pa.drawLine(QPointF(9*s,11*s), QPointF(15*s,11*s));
            break;
        }
        case Globe:
            pa.drawEllipse(QPointF(12*s,12*s), 9*s, 9*s);
            pa.drawLine(QPointF(3*s,12*s), QPointF(21*s,12*s));
            {   QPainterPath ep;
                ep.moveTo(12*s,3*s);
                ep.cubicTo(16*s,7*s, 16*s,17*s, 12*s,21*s);
                ep.cubicTo(8*s,17*s, 8*s,7*s, 12*s,3*s);
                pa.drawPath(ep);
            }
            break;
        case Refresh:
            pa.drawArc(QRectF(4*s,4*s,16*s,16*s), 30*16, 300*16);
            pa.drawLine(QPointF(20*s,4*s), QPointF(20*s,8*s));
            pa.drawLine(QPointF(16*s,4*s), QPointF(20*s,4*s));
            break;
        case Search:
            pa.drawEllipse(QPointF(11*s,11*s), 6*s, 6*s);
            pa.drawLine(QPointF(15.5*s,15.5*s), QPointF(20*s,20*s));
            break;
        case Filter:
            pa.drawLine(QPointF(4*s,6*s), QPointF(20*s,6*s));
            pa.drawLine(QPointF(7*s,12*s), QPointF(17*s,12*s));
            pa.drawLine(QPointF(10*s,18*s), QPointF(14*s,18*s));
            break;
        }
    }
private:
    Type t_; int sz_; QColor col_;
};

// ─── Filter button factory ────────────────────────────────────────────────────
static const char* kNetTabActive =
    "QPushButton { background:rgba(255,122,0,0.22); border:1px solid rgba(255,122,0,0.5);"
    " border-radius:8px; color:#FF7A00; font-size:8.5pt; font-weight:700; padding:4px 12px; }";
static const char* kNetTabInactive =
    "QPushButton { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08);"
    " border-radius:8px; color:#8A7A6E; font-size:8.5pt; font-weight:600; padding:4px 12px; }"
    "QPushButton:hover { background:rgba(255,122,0,0.10); color:#C7B6A2; }";

} // anonymous namespace

// ─── BuildNetworkPage ─────────────────────────────────────────────────────────
QWidget* MainWindow::BuildNetworkPage() {
    auto* page = new QWidget();
    page->setStyleSheet("QWidget { background: #120B06; }");
    ArmQuitGuard(page);

    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(24, 16, 24, 16);
    root->setSpacing(12);

    // ── Header ────────────────────────────────────────────────────────────────
    auto* hdr = new QHBoxLayout();
    hdr->setSpacing(10);
    auto* hdr_icon = new NetIcon(NetIcon::Shield, 26, QColor(0xFF,0x7A,0x00), page);
    hdr->addWidget(hdr_icon);

    auto* title_col = new QVBoxLayout();
    title_col->setSpacing(1);
    auto* hdr_title = new QLabel("C2 Monitor", page);
    hdr_title->setStyleSheet("font-size:15pt;font-weight:800;color:#FFFFFF;background:transparent;");
    auto* hdr_sub = new QLabel("Zero-Trust Network Surveillance", page);
    hdr_sub->setStyleSheet("font-size:8pt;color:rgba(199,182,162,0.6);background:transparent;");
    title_col->addWidget(hdr_title);
    title_col->addWidget(hdr_sub);
    hdr->addLayout(title_col);
    hdr->addStretch();

    // Auto-refresh label
    auto* auto_lbl = new QLabel("Auto 2.5s", page);
    auto_lbl->setStyleSheet("color:rgba(199,182,162,0.4);font-size:8pt;background:transparent;");
    hdr->addWidget(auto_lbl);

    auto* refresh_btn = new QPushButton(page);
    {
        auto* rl = new QHBoxLayout(refresh_btn);
        rl->setContentsMargins(10,0,12,0); rl->setSpacing(6);
        rl->addWidget(new NetIcon(NetIcon::Refresh, 14, QColor(0xFF,0x7A,0x00), refresh_btn));
        auto* rlbl = new QLabel(QString::fromUtf8("L\xe1\xba\xa0m m\xe1\xbb\x9bi"), refresh_btn);
        rlbl->setStyleSheet("background:transparent;color:#FF7A00;font-size:8.5pt;font-weight:700;");
        rl->addWidget(rlbl);
    }
    refresh_btn->setFixedHeight(32);
    refresh_btn->setMinimumWidth(100);
    refresh_btn->setStyleSheet(
        "QPushButton{background:rgba(255,122,0,0.12);border:1px solid rgba(255,122,0,0.30);"
        "border-radius:8px;}"
        "QPushButton:hover{background:rgba(255,122,0,0.22);}");
    hdr->addWidget(refresh_btn);
    root->addLayout(hdr);

    // ── Stat cards row ────────────────────────────────────────────────────────
    auto* stats_row = new QHBoxLayout();
    stats_row->setSpacing(10);

    struct StatDef { const char* utf8_label; QLabel** target; QColor accent; };
    StatDef sdefs[] = {
        { "T\xe1\xbb\x95ng",           &net_stat_total_,      QColor(0xFF,0x7A,0x00) },
        { "Established",               &net_stat_estab_,      QColor(0x4A,0xDE,0x80) },
        { "Listening",                 &net_stat_listen_,     QColor(0x07,0x87,0xFF) },
        { "Nghi ng\xe1\xbb\x9d",       &net_stat_suspicious_, QColor(0xFF,0xA5,0x00) },
        { "Nguy hi\xe1\xbb\x83m",      &net_stat_highrisk_,   QColor(0xFF,0x3A,0x3A) },
        { "Via CDN",                   &net_stat_cdn_,        QColor(0xC0,0x84,0xFF) },
    };
    for (auto& sd : sdefs) {
        auto* card = new QFrame(page);
        card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        card->setFixedHeight(60);
        card->setStyleSheet(
            QString("QFrame{background:#1C1108;border:1px solid rgba(%1,%2,%3,0.22);"
                    "border-radius:10px;}")
                .arg(sd.accent.red()).arg(sd.accent.green()).arg(sd.accent.blue()));
        auto* cl = new QVBoxLayout(card);
        cl->setContentsMargins(12, 6, 12, 6);
        cl->setSpacing(1);
        *sd.target = new QLabel("\xe2\x80\x94", card);
        (*sd.target)->setStyleSheet(
            QString("font-size:18pt;font-weight:800;color:rgb(%1,%2,%3);background:transparent;")
                .arg(sd.accent.red()).arg(sd.accent.green()).arg(sd.accent.blue()));
        auto* lbl = new QLabel(QString::fromUtf8(sd.utf8_label), card);
        lbl->setStyleSheet("font-size:7.5pt;color:rgba(199,182,162,0.6);background:transparent;");
        cl->addWidget(*sd.target);
        cl->addWidget(lbl);
        stats_row->addWidget(card);
    }
    root->addLayout(stats_row);

    // ── Filter + search row ───────────────────────────────────────────────────
    auto* filter_row = new QHBoxLayout();
    filter_row->setSpacing(8);

    auto* fi_ico = new NetIcon(NetIcon::Filter, 15, QColor(0xFF,0x7A,0x00), page);
    filter_row->addWidget(fi_ico);

    net_filter_all_  = new QPushButton(QString::fromUtf8("T\xe1\xba\xa5t c\xe1\xba\xa3"), page);
    net_filter_susp_ = new QPushButton(QString::fromUtf8("Nghi ng\xe1\xbb\x9d"), page);
    net_filter_high_ = new QPushButton(QString::fromUtf8("Nguy hi\xe1\xbb\x83m \xe2\x9a\xa0"), page);
    net_filter_all_->setFixedHeight(28);
    net_filter_susp_->setFixedHeight(28);
    net_filter_high_->setFixedHeight(28);
    net_filter_all_->setStyleSheet(kNetTabActive);
    net_filter_susp_->setStyleSheet(kNetTabInactive);
    net_filter_high_->setStyleSheet(kNetTabInactive);

    auto setFilter = [this](int mode) {
        net_filter_mode_ = mode;
        net_filter_all_->setStyleSheet(mode == 0 ? kNetTabActive : kNetTabInactive);
        net_filter_susp_->setStyleSheet(mode == 1 ? kNetTabActive : kNetTabInactive);
        net_filter_high_->setStyleSheet(mode == 2 ? kNetTabActive : kNetTabInactive);
        RefreshNetworkConnections();
    };
    QObject::connect(net_filter_all_,  &QPushButton::clicked, page, [setFilter]{ setFilter(0); });
    QObject::connect(net_filter_susp_, &QPushButton::clicked, page, [setFilter]{ setFilter(1); });
    QObject::connect(net_filter_high_, &QPushButton::clicked, page, [setFilter]{ setFilter(2); });

    filter_row->addWidget(net_filter_all_);
    filter_row->addWidget(net_filter_susp_);
    filter_row->addWidget(net_filter_high_);
    filter_row->addStretch();

    // Min Risk threshold spinner
    {
        auto* thr_lbl = new QLabel(QString::fromUtf8("Min risk:"), page);
        thr_lbl->setStyleSheet("color:rgba(199,182,162,0.55);font-size:8pt;background:transparent;");
        filter_row->addWidget(thr_lbl);

        auto* thr_spin = new QSpinBox(page);
        thr_spin->setRange(0, 80);
        thr_spin->setValue(0);
        thr_spin->setSingleStep(5);
        thr_spin->setFixedWidth(52);
        thr_spin->setFixedHeight(28);
        thr_spin->setStyleSheet(
            "QSpinBox{background:#1C1108;border:1px solid rgba(255,170,90,0.25);"
            "border-radius:7px;padding:2px 4px;color:#ECE4DA;font-size:8.5pt;}"
            "QSpinBox::up-button,QSpinBox::down-button{width:14px;border:none;"
            "background:rgba(255,122,0,0.12);}");
        QObject::connect(thr_spin, QOverload<int>::of(&QSpinBox::valueChanged), this,
            [this](int v) {
                net_min_risk_threshold_ = v;
                RefreshNetworkConnections();
            });
        filter_row->addWidget(thr_spin);
    }
    filter_row->addSpacing(4);

    // Process quick-filter
    auto* proc_search = new QLineEdit(page);
    proc_search->setPlaceholderText(QString::fromUtf8("\xf0\x9f\x94\x8d L\xe1\xbb\x8d" "c process..."));
    proc_search->setFixedWidth(180);
    proc_search->setFixedHeight(28);
    proc_search->setStyleSheet(
        "QLineEdit{background:#1C1108;border:1px solid rgba(255,170,90,0.25);border-radius:8px;"
        "padding:2px 10px;color:#ECE4DA;font-size:8.5pt;}"
        "QLineEdit:focus{border-color:rgba(255,122,0,0.5);}");
    filter_row->addWidget(proc_search);
    root->addLayout(filter_row);

    // ── Connection table ──────────────────────────────────────────────────────
    auto* tbl_card = new QFrame(page);
    tbl_card->setStyleSheet(
        "QFrame{background:#1C1108;border:1px solid rgba(255,170,90,0.15);border-radius:10px;}");
    auto* tbl_vl = new QVBoxLayout(tbl_card);
    tbl_vl->setContentsMargins(0,0,0,0);
    tbl_vl->setSpacing(0);

    // Table header bar
    auto* tbl_hdr = new QWidget(tbl_card);
    tbl_hdr->setFixedHeight(34);
    tbl_hdr->setStyleSheet(
        "background:rgba(255,122,0,0.08);border-radius:10px 10px 0 0;"
        "border-bottom:1px solid rgba(255,122,0,0.12);");
    auto* thl = new QHBoxLayout(tbl_hdr);
    thl->setContentsMargins(14,0,14,0);
    auto* th_lbl = new QLabel(QString::fromUtf8(
        "K\xe1\xba\xbft n\xe1\xbb\x91i m\xe1\xba\xa1ng — Zero-Trust C2 Analysis"), tbl_hdr);
    th_lbl->setStyleSheet("font-size:9.5pt;font-weight:700;color:#FF7A00;background:transparent;");
    thl->addWidget(th_lbl);
    thl->addStretch();
    auto* th_hint = new QLabel(QString::fromUtf8(
        "Risk: \xe2\x96\xa0 0-34 b\xc3\xacnh th\xc6\xb0\xe1\xbb\x9dng  "
        "\xe2\x96\xa0 35-69 nghi ng\xe1\xbb\x9d  "
        "\xe2\x96\xa0 70+ nguy hi\xe1\xbb\x83m"), tbl_hdr);
    th_hint->setStyleSheet("font-size:7.5pt;color:rgba(199,182,162,0.45);background:transparent;");
    thl->addWidget(th_hint);
    tbl_vl->addWidget(tbl_hdr);

    net_conn_table_ = new QTableWidget(0, 8, tbl_card);
    net_conn_table_->setHorizontalHeaderLabels({
        "Risk", "Process", "PID",
        QString::fromUtf8("Remote Host / IP"),
        QString::fromUtf8("C\xe1\xbb\x95ng"),
        "State", "CDN", QString::fromUtf8("L\xc3\xbd do") });
    net_conn_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    net_conn_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    net_conn_table_->setSelectionMode(QAbstractItemView::SingleSelection);
    net_conn_table_->verticalHeader()->setVisible(false);
    net_conn_table_->setShowGrid(false);
    net_conn_table_->setAlternatingRowColors(true);
    net_conn_table_->setSortingEnabled(true);
    net_conn_table_->setRowHeight(0, 26);
    auto* hh = net_conn_table_->horizontalHeader();
    hh->setSectionResizeMode(QHeaderView::Interactive);
    hh->setSectionResizeMode(0, QHeaderView::Fixed); net_conn_table_->setColumnWidth(0, 50);
    hh->setSectionResizeMode(1, QHeaderView::Stretch);
    hh->setSectionResizeMode(2, QHeaderView::Fixed); net_conn_table_->setColumnWidth(2, 52);
    hh->setSectionResizeMode(3, QHeaderView::Stretch);
    hh->setSectionResizeMode(4, QHeaderView::Fixed); net_conn_table_->setColumnWidth(4, 52);
    hh->setSectionResizeMode(5, QHeaderView::Fixed); net_conn_table_->setColumnWidth(5, 80);
    hh->setSectionResizeMode(6, QHeaderView::Fixed); net_conn_table_->setColumnWidth(6, 80);
    hh->setSectionResizeMode(7, QHeaderView::Stretch);
    net_conn_table_->setStyleSheet(
        "QTableWidget{background:transparent;alternate-background-color:rgba(255,122,0,0.03);"
        "color:#E8DACE;font-size:8.5pt;border:none;gridline-color:transparent;}"
        "QTableWidget::item{padding:3px 8px;}"
        "QTableWidget::item:selected{background:rgba(255,122,0,0.18);color:#fff;}"
        "QHeaderView::section{background:transparent;color:rgba(255,122,0,0.75);"
        "font-size:7.5pt;font-weight:700;border:none;"
        "border-bottom:1px solid rgba(255,122,0,0.18);padding:4px 8px;}");
    tbl_vl->addWidget(net_conn_table_);
    root->addWidget(tbl_card, 1);

    // ── Port scanner tool ─────────────────────────────────────────────────────
    auto* scan_card = new QFrame(page);
    scan_card->setFixedHeight(44);
    scan_card->setStyleSheet(
        "QFrame{background:#1C1108;border:1px solid rgba(255,122,0,0.15);border-radius:10px;}");
    auto* scan_row = new QHBoxLayout(scan_card);
    scan_row->setContentsMargins(14,0,14,0); scan_row->setSpacing(8);

    auto* si = new NetIcon(NetIcon::Search, 14, QColor(0xFF,0x7A,0x00), scan_card);
    scan_row->addWidget(si);
    auto* sl = new QLabel("Port Scanner:", scan_card);
    sl->setStyleSheet("color:#FF7A00;font-size:8.5pt;font-weight:700;background:transparent;");
    scan_row->addWidget(sl);

    auto* host_edit = new QLineEdit(scan_card);
    host_edit->setPlaceholderText("Host (192.168.1.1)");
    host_edit->setFixedWidth(160); host_edit->setFixedHeight(28);
    host_edit->setStyleSheet(
        "QLineEdit{background:rgba(255,122,0,0.07);border:1px solid rgba(255,122,0,0.2);"
        "border-radius:6px;color:#fff;font-size:8.5pt;padding:2px 8px;}"
        "QLineEdit:focus{border-color:rgba(255,122,0,0.5);}");
    scan_row->addWidget(host_edit);

    auto* ports_edit = new QLineEdit(scan_card);
    ports_edit->setPlaceholderText(QString::fromUtf8("C\xe1\xbb\x95ng (80,443,3389)"));
    ports_edit->setFixedWidth(160); ports_edit->setFixedHeight(28);
    ports_edit->setStyleSheet(host_edit->styleSheet());
    scan_row->addWidget(ports_edit);

    auto* scan_btn = new QPushButton(QString::fromUtf8("Qu\xc3\xa9t"), scan_card);
    scan_btn->setFixedSize(64, 28);
    scan_btn->setStyleSheet(
        "QPushButton{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "stop:0 #C05500,stop:1 #FF7A00);color:#fff;font-weight:700;font-size:8.5pt;"
        "border-radius:6px;border:none;}"
        "QPushButton:hover{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "stop:0 #D06000,stop:1 #FF9030);}"
        "QPushButton:disabled{background:rgba(255,255,255,0.07);color:rgba(255,255,255,0.2);}");
    scan_row->addWidget(scan_btn);
    scan_row->addStretch();

    auto* scan_result = new QLabel("", scan_card);
    scan_result->setStyleSheet("color:rgba(199,182,162,0.8);font-size:8pt;background:transparent;");
    scan_row->addWidget(scan_result);
    root->addWidget(scan_card);

    // Port scanner logic
    QObject::connect(scan_btn, &QPushButton::clicked, this,
            [this, host_edit, ports_edit, scan_btn, scan_result] {
        const QString host = host_edit->text().trimmed();
        const QString ports_str = ports_edit->text().trimmed();
        if (host.isEmpty() || ports_str.isEmpty()) {
            scan_result->setText(QString::fromUtf8("\xe2\x9a\xa0 Nh\xe1\xba\xadp host v\xc3\xa0 c\xe1\xbb\x95ng"));
            return;
        }
        scan_btn->setEnabled(false);
        scan_result->setText(QString::fromUtf8("\xe2\x8f\xb3 \xc4\x90" "ang qu\xc3\xa9t..."));
        const QStringList port_list = ports_str.split(',', Qt::SkipEmptyParts);
        std::thread([this, host, port_list, scan_btn, scan_result] {
            QString open_ports;
            int open_count = 0, closed_count = 0;
            for (const QString& p_str : port_list) {
                if (AppQuitting().load()) return;
                const int port = p_str.trimmed().toInt();
                if (port <= 0 || port > 65535) continue;
                SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s == INVALID_SOCKET) continue;
                DWORD to = 2000;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&to, sizeof(to));
                sockaddr_in sa{};
                sa.sin_family = AF_INET;
                sa.sin_port = htons((u_short)port);
                inet_pton(AF_INET, host.toStdString().c_str(), &sa.sin_addr);
                const bool ok = (::connect(s, (sockaddr*)&sa, sizeof(sa)) == 0);
                closesocket(s);
                if (ok) {
                    if (!open_ports.isEmpty()) open_ports += ", ";
                    open_ports += QString::number(port);
                    ++open_count;
                } else {
                    ++closed_count;
                }
            }
            const QString result = open_count > 0
                ? QString::fromUtf8("\xe2\x9c\x93 M\xe1\xbb\x9f: [%1]  \xe2\x80\xa2  \xc4\x90\xc3\xb3ng: %2")
                      .arg(open_ports).arg(closed_count)
                : QString::fromUtf8("\xf0\x9f\x94\x92 T\xe1\xba\xa5t c\xe1\xba\xa3 %1 c\xe1\xbb\x95ng \xc4\x91\xc3\xb3ng")
                      .arg(closed_count);
            if (AppQuitting().load()) return;
            QMetaObject::invokeMethod(this, [scan_btn, scan_result, result] {
                scan_result->setText(result);
                scan_btn->setEnabled(true);
            }, Qt::QueuedConnection);
        }).detach();
    });

    // Process-name filter wiring
    QObject::connect(proc_search, &QLineEdit::textChanged, this,
            [this](const QString& text) {
        if (!net_conn_table_) return;
        for (int i = 0; i < net_conn_table_->rowCount(); ++i) {
            const auto* item = net_conn_table_->item(i, 1);
            const bool match = text.isEmpty()
                || (item && item->text().contains(text, Qt::CaseInsensitive));
            net_conn_table_->setRowHidden(i, !match);
        }
    });

    // Row click → Process Hunt
    QObject::connect(net_conn_table_, &QTableWidget::currentCellChanged, this,
            [this](int row, int /*col*/, int /*prevRow*/, int /*prevCol*/) {
        if (row < 0 || !net_conn_table_) return;
        const auto* pid_item = net_conn_table_->item(row, 2);
        if (!pid_item || pid_item->text().isEmpty()) return;
        const uint32_t pid = pid_item->text().toUInt();
        if (pid > 0) HuntProcess(pid);
    });

    // ── Process Hunt Panel ────────────────────────────────────────────────────
    net_hunt_panel_ = new QFrame(page);
    net_hunt_panel_->setFixedHeight(190);
    net_hunt_panel_->setVisible(false);
    net_hunt_panel_->setStyleSheet(
        "QFrame{background:#150E08;border:1px solid rgba(255,122,0,0.35);"
        "border-radius:10px;}");

    auto* hunt_vl = new QVBoxLayout(net_hunt_panel_);
    hunt_vl->setContentsMargins(14, 10, 14, 10);
    hunt_vl->setSpacing(8);

    // Hunt header row
    auto* hunt_hdr = new QHBoxLayout();
    hunt_hdr->setSpacing(8);
    auto* hunt_ico = new NetIcon(NetIcon::Search, 16, QColor(0xFF,0x7A,0x00), net_hunt_panel_);
    hunt_hdr->addWidget(hunt_ico);
    auto* hunt_mode_lbl = new QLabel(QString::fromUtf8(
        "\xf0\x9f\x8e\xaf Process Hunt"), net_hunt_panel_);
    hunt_mode_lbl->setStyleSheet(
        "font-size:9pt;font-weight:800;color:#FF7A00;background:transparent;");
    hunt_hdr->addWidget(hunt_mode_lbl);
    hunt_hdr->addSpacing(6);
    net_hunt_title_lbl_ = new QLabel("—", net_hunt_panel_);
    net_hunt_title_lbl_->setStyleSheet(
        "font-size:9pt;font-weight:700;color:#FFFFFF;background:transparent;");
    hunt_hdr->addWidget(net_hunt_title_lbl_);
    hunt_hdr->addStretch();

    // Action buttons
    auto makeActionBtn = [&](const char* utf8_label, QColor col) {
        auto* btn = new QPushButton(net_hunt_panel_);
        btn->setText(QString::fromUtf8(utf8_label));
        btn->setFixedHeight(26);
        btn->setMinimumWidth(90);
        btn->setStyleSheet(
            QString("QPushButton{background:rgba(%1,%2,%3,0.15);"
                    "border:1px solid rgba(%1,%2,%3,0.45);border-radius:7px;"
                    "color:rgb(%1,%2,%3);font-size:8pt;font-weight:700;padding:0 10px;}"
                    "QPushButton:hover{background:rgba(%1,%2,%3,0.28);}"
                    "QPushButton:disabled{opacity:0.4;}")
                .arg(col.red()).arg(col.green()).arg(col.blue()));
        return btn;
    };
    net_hunt_kill_btn_ = makeActionBtn("\xe2\x9c\x95 Kill Process", QColor(0xFF,0x3A,0x3A));
    auto* hunt_scan_btn  = makeActionBtn("\xf0\x9f\x94\x8d Scan Memory", QColor(0xFF,0x7A,0x00));
    auto* hunt_copy_btn  = makeActionBtn("\xf0\x9f\x93\x8b Copy Path",   QColor(0x4A,0xDE,0x80));
    auto* hunt_safe_btn  = makeActionBtn("\xe2\x9c\x93 Mark Safe",        QColor(0x07,0xC9,0x7A));
    auto* hunt_close_btn = makeActionBtn("\xe2\x9c\x95 " "\xc4\x90\xc3\xb3ng", QColor(0x8A,0x7A,0x6E));
    hunt_hdr->addWidget(net_hunt_kill_btn_);
    hunt_hdr->addWidget(hunt_scan_btn);
    hunt_hdr->addWidget(hunt_copy_btn);
    hunt_hdr->addWidget(hunt_safe_btn);
    hunt_hdr->addWidget(hunt_close_btn);
    hunt_vl->addLayout(hunt_hdr);

    // Process info row
    auto* hunt_info = new QHBoxLayout();
    hunt_info->setSpacing(16);
    net_hunt_path_lbl_ = new QLabel("", net_hunt_panel_);
    net_hunt_path_lbl_->setStyleSheet(
        "font-size:7.5pt;color:rgba(199,182,162,0.7);background:transparent;");
    net_hunt_path_lbl_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    hunt_info->addWidget(net_hunt_path_lbl_, 1);
    net_hunt_parent_lbl_ = new QLabel("", net_hunt_panel_);
    net_hunt_parent_lbl_->setStyleSheet(
        "font-size:7.5pt;color:rgba(199,182,162,0.5);background:transparent;");
    hunt_info->addWidget(net_hunt_parent_lbl_);
    net_hunt_risk_lbl_ = new QLabel("", net_hunt_panel_);
    net_hunt_risk_lbl_->setStyleSheet(
        "font-size:7.5pt;color:#FF7A00;font-weight:700;background:transparent;");
    hunt_info->addWidget(net_hunt_risk_lbl_);
    hunt_vl->addLayout(hunt_info);

    // Connections sub-table
    net_hunt_table_ = new QTableWidget(0, 5, net_hunt_panel_);
    net_hunt_table_->setHorizontalHeaderLabels({
        "Risk", QString::fromUtf8("Remote"), "Port", "State", QString::fromUtf8("L\xc3\xbd do") });
    net_hunt_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    net_hunt_table_->setSelectionMode(QAbstractItemView::NoSelection);
    net_hunt_table_->verticalHeader()->setVisible(false);
    net_hunt_table_->setShowGrid(false);
    net_hunt_table_->setFixedHeight(82);
    auto* hh2 = net_hunt_table_->horizontalHeader();
    hh2->setSectionResizeMode(QHeaderView::Interactive);
    hh2->setSectionResizeMode(0, QHeaderView::Fixed); net_hunt_table_->setColumnWidth(0, 44);
    hh2->setSectionResizeMode(1, QHeaderView::Stretch);
    hh2->setSectionResizeMode(2, QHeaderView::Fixed); net_hunt_table_->setColumnWidth(2, 48);
    hh2->setSectionResizeMode(3, QHeaderView::Fixed); net_hunt_table_->setColumnWidth(3, 80);
    hh2->setSectionResizeMode(4, QHeaderView::Stretch);
    net_hunt_table_->setStyleSheet(
        "QTableWidget{background:rgba(0,0,0,0.2);border:none;color:#E8DACE;font-size:8pt;}"
        "QTableWidget::item{padding:2px 6px;}"
        "QHeaderView::section{background:transparent;color:rgba(255,122,0,0.6);"
        "font-size:7pt;font-weight:700;border:none;"
        "border-bottom:1px solid rgba(255,122,0,0.15);padding:2px 6px;}");
    hunt_vl->addWidget(net_hunt_table_);

    // Hunt button actions
    QObject::connect(hunt_close_btn, &QPushButton::clicked, this, [this] {
        if (net_hunt_panel_) net_hunt_panel_->setVisible(false);
        if (net_conn_table_) net_conn_table_->clearSelection();
        net_hunted_pid_ = 0;
    });

    QObject::connect(net_hunt_kill_btn_, &QPushButton::clicked, this, [this] {
        if (net_hunted_pid_ == 0) return;
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, net_hunted_pid_);
        if (h) {
            TerminateProcess(h, 1);
            CloseHandle(h);
            if (net_hunt_kill_btn_) {
                net_hunt_kill_btn_->setText(QString::fromUtf8("\xe2\x9c\x93 Killed"));
                net_hunt_kill_btn_->setEnabled(false);
            }
            QTimer::singleShot(1500, this, &MainWindow::RefreshNetworkConnections);
        }
    });

    QObject::connect(hunt_scan_btn, &QPushButton::clicked, this, [this, hunt_scan_btn] {
        if (net_hunted_pid_ == 0) return;
        hunt_scan_btn->setEnabled(false);
        hunt_scan_btn->setText(QString::fromUtf8("\xe2\x8f\xb3 Scanning..."));
        const uint32_t pid = net_hunted_pid_;
        std::thread([this, pid, hunt_scan_btn] {
            const int hits = engine_->ScanProcessMemory(pid);
            if (AppQuitting().load()) return;
            QMetaObject::invokeMethod(this, [hunt_scan_btn, hits] {
                hunt_scan_btn->setText(
                    QString("\xf0\x9f\x94\x8d %1 hit(s)").arg(hits));
                hunt_scan_btn->setEnabled(true);
            }, Qt::QueuedConnection);
        }).detach();
    });

    QObject::connect(hunt_copy_btn, &QPushButton::clicked, this, [this] {
        if (!net_hunt_path_lbl_) return;
        QApplication::clipboard()->setText(net_hunt_path_lbl_->text());
    });

    // Mark Safe — whitelist all connections from this PID in current snapshot
    QObject::connect(hunt_safe_btn, &QPushButton::clicked, this,
            [this, hunt_safe_btn] {
        if (net_hunted_pid_ == 0 || !net_conn_table_) return;
        const uint32_t pid = net_hunted_pid_;
        int marked = 0;
        for (int i = 0; i < net_conn_table_->rowCount(); ++i) {
            const auto* pid_it  = net_conn_table_->item(i, 2);
            const auto* proc_it = net_conn_table_->item(i, 1);
            const auto* rem_it  = net_conn_table_->item(i, 3);
            const auto* prt_it  = net_conn_table_->item(i, 4);
            if (!pid_it || pid_it->text().toUInt() != pid) continue;
            // Reconstruct cache key
            std::string proc_lower = proc_it ? proc_it->text().toLower().toStdString() : "";
            // remote_display may include "(ip)" — extract raw IP
            QString rem_raw = rem_it ? rem_it->text() : "";
            const int paren = rem_raw.lastIndexOf('(');
            if (paren >= 0) rem_raw = rem_raw.mid(paren + 1).remove(')').trimmed();
            const std::string ip_str = rem_raw.toStdString();
            const int port = prt_it ? prt_it->text().toInt() : 0;
            const std::string key = proc_lower + "|" + ip_str + "|" + std::to_string(port);
            {
                std::lock_guard<std::mutex> lk(net_dns_mutex_);
                net_safe_set_.insert(key);
                net_score_cache_.erase(key); // force cache refresh → score 0
            }
            ++marked;
        }
        hunt_safe_btn->setText(QString("\xe2\x9c\x93 Safe (%1)").arg(marked));
        if (net_hunt_risk_lbl_)
            net_hunt_risk_lbl_->setText(
                "<span style='color:#07C97A;'>User Verified \xe2\x80\x94 Whitelisted</span>");
        QTimer::singleShot(500, this, &MainWindow::RefreshNetworkConnections);
    });

    root->addWidget(net_hunt_panel_);

    // ── Timers ────────────────────────────────────────────────────────────────
    auto* refresh_timer = new QTimer(page);
    refresh_timer->setInterval(2500);
    QObject::connect(refresh_timer, &QTimer::timeout, this, &MainWindow::RefreshNetworkConnections);
    refresh_timer->start();

    QObject::connect(refresh_btn, &QPushButton::clicked, this, &MainWindow::RefreshNetworkConnections);

    QTimer::singleShot(0, this, &MainWindow::RefreshNetworkConnections);
    return page;
}

// ─── RefreshNetworkConnections ────────────────────────────────────────────────
void MainWindow::RefreshNetworkConnections() {
    if (!net_conn_table_) return;

    // Run netstat and process-list in a background thread, update UI via invokeMethod
    std::thread([this] {
        // ── Collect TCP/UDP connections via iphlpapi ──────────────────────────
        struct Conn {
            QString proto, local, remote_ip;
            int     remote_port = 0;
            QString state;
            DWORD   pid = 0;
        };
        std::vector<Conn> conns;

        // TCP
        DWORD tcp_size = 0;
        GetExtendedTcpTable(nullptr, &tcp_size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> tcp_buf(tcp_size + 256);
        if (GetExtendedTcpTable(tcp_buf.data(), &tcp_size, FALSE, AF_INET,
                                TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(tcp_buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& row = t->table[i];
                char local_ip[64], remote_ip[64];
                in_addr la{}, ra{};
                la.s_addr = row.dwLocalAddr;
                ra.s_addr = row.dwRemoteAddr;
                inet_ntop(AF_INET, &la, local_ip, sizeof(local_ip));
                inet_ntop(AF_INET, &ra, remote_ip, sizeof(remote_ip));
                const int lport = ntohs((u_short)row.dwLocalPort);
                const int rport = ntohs((u_short)row.dwRemotePort);
                const char* state_str = "";
                switch (row.dwState) {
                    case MIB_TCP_STATE_LISTEN:       state_str = "LISTENING";    break;
                    case MIB_TCP_STATE_ESTAB:        state_str = "ESTABLISHED";  break;
                    case MIB_TCP_STATE_TIME_WAIT:    state_str = "TIME_WAIT";    break;
                    case MIB_TCP_STATE_CLOSE_WAIT:   state_str = "CLOSE_WAIT";   break;
                    case MIB_TCP_STATE_SYN_SENT:     state_str = "SYN_SENT";     break;
                    case MIB_TCP_STATE_SYN_RCVD:     state_str = "SYN_RCVD";     break;
                    case MIB_TCP_STATE_FIN_WAIT1:    state_str = "FIN_WAIT1";    break;
                    case MIB_TCP_STATE_FIN_WAIT2:    state_str = "FIN_WAIT2";    break;
                    case MIB_TCP_STATE_LAST_ACK:     state_str = "LAST_ACK";     break;
                    case MIB_TCP_STATE_CLOSED:       state_str = "CLOSED";       break;
                    default:                         state_str = "UNKNOWN";       break;
                }
                Conn c;
                c.proto      = "TCP";
                c.local      = QString("%1:%2").arg(local_ip).arg(lport);
                c.remote_ip  = remote_ip;
                c.remote_port = rport;
                c.state      = state_str;
                c.pid        = row.dwOwningPid;
                conns.push_back(c);
            }
        }

        // UDP
        DWORD udp_size = 0;
        GetExtendedUdpTable(nullptr, &udp_size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0);
        std::vector<BYTE> udp_buf(udp_size + 256);
        if (GetExtendedUdpTable(udp_buf.data(), &udp_size, FALSE, AF_INET,
                                UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(udp_buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& row = t->table[i];
                char local_ip[64];
                in_addr la{};
                la.s_addr = row.dwLocalAddr;
                inet_ntop(AF_INET, &la, local_ip, sizeof(local_ip));
                const int lport = ntohs((u_short)row.dwLocalPort);
                Conn c;
                c.proto      = "UDP";
                c.local      = QString("%1:%2").arg(local_ip).arg(lport);
                c.remote_ip  = "*";
                c.remote_port = 0;
                c.state      = "LISTEN";
                c.pid        = row.dwOwningPid;
                conns.push_back(c);
            }
        }

        // ── Process names via psapi ───────────────────────────────────────────
        std::unordered_map<DWORD, std::string> pid_names;
        {
            DWORD pids[1024]; DWORD needed = 0;
            if (EnumProcesses(pids, sizeof(pids), &needed)) {
                const DWORD count = needed / sizeof(DWORD);
                for (DWORD i = 0; i < count; ++i) {
                    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
                    if (!h) continue;
                    char name[MAX_PATH] = {};
                    DWORD sz = MAX_PATH;
                    QueryFullProcessImageNameA(h, 0, name, &sz);
                    CloseHandle(h);
                    const std::string full(name);
                    const auto slash = full.rfind('\\');
                    const std::string base = (slash != std::string::npos)
                        ? full.substr(slash + 1) : full;
                    pid_names[pids[i]] = base;
                }
            }
        }

        // ── Hostname lookup from cache ────────────────────────────────────────
        // Collect unique remote IPs not yet cached
        std::vector<std::string> uncached;
        {
            std::lock_guard<std::mutex> lk(net_dns_mutex_);
            for (const auto& c : conns) {
                const std::string ip = c.remote_ip.toStdString();
                if (ip == "*" || ip == "0.0.0.0" || net_dns_cache_.count(ip)) continue;
                const uint32_t h = ParseIpBe(ip);
                if (IsPrivateIp(h) || h == 0) continue;
                // Pre-fill so we don't fire duplicate lookups
                net_dns_cache_[ip] = "";
                uncached.push_back(ip);
            }
        }
        // Async resolve new IPs (limited batch to avoid stalling)
        if (!uncached.empty() && !net_dns_running_.exchange(true)) {
            std::thread([this, uncached = std::move(uncached)] {
                for (const auto& ip : uncached) {
                    sockaddr_in sa{};
                    sa.sin_family = AF_INET;
                    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
                    char host[NI_MAXHOST] = {};
                    const int r = getnameinfo(
                        (sockaddr*)&sa, sizeof(sa),
                        host, NI_MAXHOST,
                        nullptr, 0,
                        NI_NAMEREQD);
                    {
                        std::lock_guard<std::mutex> lk(net_dns_mutex_);
                        net_dns_cache_[ip] = (r == 0 && host[0]) ? host : "";
                    }
                }
                net_dns_running_ = false;
                if (AppQuitting().load()) return;
                // Re-refresh UI to show newly resolved hostnames
                QMetaObject::invokeMethod(this,
                    [this] { RefreshNetworkConnections(); }, Qt::QueuedConnection);
            }).detach();
        }

        // ── Score and build table rows ────────────────────────────────────────
        struct Row {
            int     risk;
            QString proc, pid_str, remote_display, port_str, state, cdn, label;
            QColor  row_tint;
        };
        std::vector<Row> rows;
        int total = 0, estab = 0, listen = 0, suspicious = 0, highrisk = 0, via_cdn = 0;

        for (const auto& c : conns) {
            const std::string proc = pid_names.count(c.pid) ? pid_names.at(c.pid) : "—";
            std::string proc_lower = proc;
            std::transform(proc_lower.begin(), proc_lower.end(), proc_lower.begin(), ::tolower);

            const std::string ip_str = c.remote_ip.toStdString();

            // Hostname from cache
            std::string hostname;
            {
                std::lock_guard<std::mutex> lk(net_dns_mutex_);
                auto it = net_dns_cache_.find(ip_str);
                if (it != net_dns_cache_.end()) hostname = it->second;
            }

            const bool established = (c.state == "ESTABLISHED");

            // Build cache key
            const std::string cache_key =
                proc_lower + "|" + ip_str + "|" + std::to_string(c.remote_port);

            // Check user safe-list first
            RiskResult rr;
            {
                std::lock_guard<std::mutex> lk(net_dns_mutex_);
                if (net_safe_set_.count(cache_key)) {
                    rr = {0, "User Verified", ""};
                } else {
                    // Check score cache (TTL-based)
                    auto it = net_score_cache_.find(cache_key);
                    const int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    if (it != net_score_cache_.end()
                        && (now_s - it->second.ts) < CacheTtl(it->second.score)) {
                        // Use cached score — skip expensive re-evaluation
                        rr = {it->second.score, it->second.label, it->second.cdn};
                    } else {
                        // Re-score and cache result
                        rr = ScoreConn(proc_lower, ip_str, hostname, c.remote_port, established);
                        net_score_cache_[cache_key] = {rr.score, rr.label, rr.cdn, now_s};
                    }
                }
            }

            // Filter by mode and min-risk threshold
            if (net_filter_mode_ == 1 && rr.score < 35) continue;
            if (net_filter_mode_ == 2 && rr.score < 70) continue;
            if (rr.score < net_min_risk_threshold_) continue;

            // Stats
            ++total;
            if (c.state == "ESTABLISHED") ++estab;
            if (c.state == "LISTENING")   ++listen;
            if (rr.score >= 35 && rr.score < 70) ++suspicious;
            if (rr.score >= 70) ++highrisk;
            if (!rr.cdn.empty()) ++via_cdn;

            Row row;
            row.risk = rr.score;
            row.proc = QString::fromStdString(proc);
            row.pid_str = (c.pid > 0) ? QString::number(c.pid) : "";

            // Remote display: prefer hostname, fall back to IP
            if (!hostname.empty())
                row.remote_display = QString::fromStdString(hostname)
                    + " (" + c.remote_ip + ")";
            else
                row.remote_display = c.remote_ip;

            row.port_str = (c.remote_port > 0) ? QString::number(c.remote_port) : "";
            row.state    = c.state;
            row.cdn      = QString::fromStdString(rr.cdn);
            row.label    = QString::fromStdString(rr.label);

            if      (rr.score >= 70) row.row_tint = QColor(0xFF, 0x3A, 0x3A, 18);
            else if (rr.score >= 35) row.row_tint = QColor(0xFF, 0xA5, 0x00, 14);
            else                     row.row_tint = QColor(0, 0, 0, 0);

            rows.push_back(std::move(row));
        }

        // Evict score cache entries for connections that no longer exist
        {
            std::unordered_set<std::string> active_keys;
            for (const auto& c : conns) {
                const std::string pn = pid_names.count(c.pid) ? pid_names.at(c.pid) : "";
                std::string pl = pn;
                std::transform(pl.begin(), pl.end(), pl.begin(), ::tolower);
                active_keys.insert(pl + "|" + c.remote_ip.toStdString()
                                      + "|" + std::to_string(c.remote_port));
            }
            std::lock_guard<std::mutex> lk(net_dns_mutex_);
            for (auto it = net_score_cache_.begin(); it != net_score_cache_.end(); ) {
                if (!active_keys.count(it->first)) it = net_score_cache_.erase(it);
                else ++it;
            }
        }

        // Sort: highest risk first
        std::stable_sort(rows.begin(), rows.end(),
            [](const Row& a, const Row& b) { return a.risk > b.risk; });

        // ── Push to UI thread ─────────────────────────────────────────────────
        if (AppQuitting().load()) return;
        QMetaObject::invokeMethod(this,
            [this, rows = std::move(rows),
             total, estab, listen, suspicious, highrisk, via_cdn]() mutable
        {
            if (net_stat_total_)      net_stat_total_->setText(QString::number(total));
            if (net_stat_estab_)      net_stat_estab_->setText(QString::number(estab));
            if (net_stat_listen_)     net_stat_listen_->setText(QString::number(listen));
            if (net_stat_suspicious_) net_stat_suspicious_->setText(QString::number(suspicious));
            if (net_stat_highrisk_)   net_stat_highrisk_->setText(QString::number(highrisk));
            if (net_stat_cdn_)        net_stat_cdn_->setText(QString::number(via_cdn));

            if (!net_conn_table_) return;
            net_conn_table_->setSortingEnabled(false);
            net_conn_table_->setRowCount(0);
            net_conn_table_->setRowCount((int)rows.size());

            for (int i = 0; i < (int)rows.size(); ++i) {
                const Row& r = rows[i];
                net_conn_table_->setRowHeight(i, 24);

                // Col 0 — risk score text (color-coded)
                auto* risk_item = new QTableWidgetItem(QString::number(r.risk));
                risk_item->setTextAlignment(Qt::AlignCenter);
                if      (r.risk >= 70) risk_item->setForeground(QColor(0xFF,0x3A,0x3A));
                else if (r.risk >= 35) risk_item->setForeground(QColor(0xFF,0xA5,0x00));
                else                   risk_item->setForeground(QColor(0x4A,0xDE,0x80));
                risk_item->setData(Qt::UserRole, r.risk); // for sorting
                net_conn_table_->setItem(i, 0, risk_item);

                // Col 1 — Process
                auto* proc_item = new QTableWidgetItem(r.proc);
                if (r.risk >= 70)      proc_item->setForeground(QColor(0xFF,0x7A,0x7A));
                else if (r.risk >= 35) proc_item->setForeground(QColor(0xFF,0xC0,0x80));
                net_conn_table_->setItem(i, 1, proc_item);

                // Col 2 — PID
                auto* pid_item = new QTableWidgetItem(r.pid_str);
                pid_item->setForeground(QColor(0x8A,0x7A,0x6E));
                net_conn_table_->setItem(i, 2, pid_item);

                // Col 3 — Remote host/IP
                net_conn_table_->setItem(i, 3, new QTableWidgetItem(r.remote_display));

                // Col 4 — Port
                net_conn_table_->setItem(i, 4, new QTableWidgetItem(r.port_str));

                // Col 5 — State with color
                auto* state_item = new QTableWidgetItem(r.state);
                if      (r.state == "ESTABLISHED") state_item->setForeground(QColor(0x4A,0xDE,0x80));
                else if (r.state == "LISTENING")   state_item->setForeground(QColor(0xFF,0xB7,0x66));
                else if (r.state == "TIME_WAIT")   state_item->setForeground(QColor(0xFF,0x5A,0x6A));
                else                               state_item->setForeground(QColor(0x8A,0x7A,0x6E));
                net_conn_table_->setItem(i, 5, state_item);

                // Col 6 — CDN
                if (!r.cdn.isEmpty()) {
                    auto* cdn_item = new QTableWidgetItem(r.cdn);
                    cdn_item->setForeground(QColor(0xC0,0x84,0xFF));
                    net_conn_table_->setItem(i, 6, cdn_item);
                } else {
                    net_conn_table_->setItem(i, 6, new QTableWidgetItem(""));
                }

                // Col 7 — Risk label
                auto* lbl_item = new QTableWidgetItem(r.label);
                lbl_item->setForeground(QColor(0x8A,0x7A,0x6E));
                net_conn_table_->setItem(i, 7, lbl_item);

                // Row background tint (semi-transparent red/orange for high risk)
                if (r.row_tint.alpha() > 0) {
                    for (int col = 0; col < 8; ++col) {
                        auto* it = net_conn_table_->item(i, col);
                        if (it) it->setBackground(r.row_tint);
                    }
                }
            }
            net_conn_table_->setSortingEnabled(true);
        }, Qt::QueuedConnection);
    }).detach();
}

// ─── HuntProcess ─────────────────────────────────────────────────────────────
void MainWindow::HuntProcess(uint32_t pid) {
    if (!net_hunt_panel_) return;
    net_hunted_pid_ = pid;

    // Reset kill button
    if (net_hunt_kill_btn_) {
        net_hunt_kill_btn_->setText(QString::fromUtf8("\xe2\x9c\x95 Kill Process"));
        net_hunt_kill_btn_->setEnabled(true);
    }

    // Show panel immediately with PID while details load
    net_hunt_title_lbl_->setText(QString("PID %1 \xe2\x80\x94 loading...").arg(pid));
    net_hunt_path_lbl_->setText("");
    net_hunt_parent_lbl_->setText("");
    net_hunt_risk_lbl_->setText("");
    if (net_hunt_table_) net_hunt_table_->setRowCount(0);
    net_hunt_panel_->setVisible(true);

    // Gather process details in background
    std::thread([this, pid] {
        // Full image path
        std::string full_path;
        std::string proc_name;
        {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (h) {
                char buf[MAX_PATH] = {};
                DWORD sz = MAX_PATH;
                QueryFullProcessImageNameA(h, 0, buf, &sz);
                CloseHandle(h);
                full_path = buf;
                const auto sl = full_path.rfind('\\');
                proc_name = (sl != std::string::npos) ? full_path.substr(sl+1) : full_path;
            }
        }
        if (proc_name.empty()) proc_name = "PID " + std::to_string(pid);

        // Parent PID + name
        uint32_t parent_pid = 0;
        std::string parent_name;
        {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
                if (Process32FirstW(snap, &pe)) {
                    do {
                        if (pe.th32ProcessID == pid) {
                            parent_pid = pe.th32ParentProcessID;
                        }
                    } while (Process32NextW(snap, &pe));
                }
                // Now look up parent name
                if (parent_pid) {
                    PROCESSENTRY32W pe2{}; pe2.dwSize = sizeof(pe2);
                    Process32FirstW(snap, &pe2);
                    do {
                        if (pe2.th32ProcessID == parent_pid) {
                            char nb[260] = {};
                            WideCharToMultiByte(CP_UTF8, 0, pe2.szExeFile, -1,
                                               nb, sizeof(nb), nullptr, nullptr);
                            parent_name = nb;
                            break;
                        }
                    } while (Process32NextW(snap, &pe2));
                }
                CloseHandle(snap);
            }
        }

        // Collect all connections for this PID from current table data
        struct HuntConn { int risk; QString remote; QString port; QString state; QString label; };
        std::vector<HuntConn> hconns;
        int max_risk = 0;
        QString max_label;

        // Re-read the connections table (already populated, read from UI — must do on UI thread)
        // We'll pass the table scan to the invokeMethod callback
        if (AppQuitting().load()) return;
        QMetaObject::invokeMethod(this,
            [this, pid, proc_name, full_path, parent_pid, parent_name, max_risk, max_label]() mutable
        {
            if (!net_hunt_panel_ || net_hunted_pid_ != pid) return;

            // Collect connections for this PID from main table
            std::vector<std::tuple<int,QString,QString,QString,QString>> hconns;
            if (net_conn_table_) {
                for (int i = 0; i < net_conn_table_->rowCount(); ++i) {
                    const auto* pid_it = net_conn_table_->item(i, 2);
                    if (!pid_it || pid_it->text().toUInt() != pid) continue;
                    const int   risk  = net_conn_table_->item(i,0)
                                        ? net_conn_table_->item(i,0)->text().toInt() : 0;
                    const QString rem = net_conn_table_->item(i,3)
                                        ? net_conn_table_->item(i,3)->text() : "";
                    const QString prt = net_conn_table_->item(i,4)
                                        ? net_conn_table_->item(i,4)->text() : "";
                    const QString st  = net_conn_table_->item(i,5)
                                        ? net_conn_table_->item(i,5)->text() : "";
                    const QString lbl = net_conn_table_->item(i,7)
                                        ? net_conn_table_->item(i,7)->text() : "";
                    if (risk > max_risk) { max_risk = risk; max_label = lbl; }
                    hconns.emplace_back(risk, rem, prt, st, lbl);
                }
            }

            // Update title
            net_hunt_title_lbl_->setText(
                QString::fromStdString(proc_name)
                + QString(" (PID %1)").arg(pid));

            // Path (truncate if too long)
            const QString path_q = QString::fromStdString(full_path);
            net_hunt_path_lbl_->setText(
                path_q.length() > 80 ? "..." + path_q.right(77) : path_q);
            net_hunt_path_lbl_->setToolTip(path_q);

            // Parent
            if (parent_pid) {
                net_hunt_parent_lbl_->setText(
                    QString::fromUtf8("Parent: ")
                    + QString::fromStdString(parent_name.empty() ? "?" : parent_name)
                    + QString(" (PID %1)").arg(parent_pid));
            }

            // Risk summary
            if (max_risk > 0) {
                const char* risk_color = max_risk >= 70 ? "#FF3A3A"
                                       : max_risk >= 35 ? "#FFA500" : "#4ADE80";
                net_hunt_risk_lbl_->setText(
                    QString("<span style='color:%1;'>Risk %2</span>%3")
                        .arg(risk_color).arg(max_risk)
                        .arg(max_label.isEmpty() ? "" : " — " + max_label));
            } else {
                net_hunt_risk_lbl_->setText(
                    QString::fromUtf8("<span style='color:#4ADE80;'>Risk 0 — OK</span>"));
            }
            net_hunt_risk_lbl_->setTextFormat(Qt::RichText);

            // Populate hunt sub-table
            if (net_hunt_table_) {
                net_hunt_table_->setSortingEnabled(false);
                net_hunt_table_->setRowCount((int)hconns.size());
                for (int i = 0; i < (int)hconns.size(); ++i) {
                    const auto& [risk, rem, prt, st, lbl] = hconns[i];
                    net_hunt_table_->setRowHeight(i, 20);

                    auto* ri = new QTableWidgetItem(QString::number(risk));
                    ri->setTextAlignment(Qt::AlignCenter);
                    ri->setForeground(risk >= 70 ? QColor(0xFF,0x3A,0x3A)
                                   : risk >= 35 ? QColor(0xFF,0xA5,0x00)
                                               : QColor(0x4A,0xDE,0x80));
                    net_hunt_table_->setItem(i, 0, ri);
                    net_hunt_table_->setItem(i, 1, new QTableWidgetItem(rem));
                    net_hunt_table_->setItem(i, 2, new QTableWidgetItem(prt));

                    auto* si = new QTableWidgetItem(st);
                    si->setForeground(st == "ESTABLISHED" ? QColor(0x4A,0xDE,0x80)
                                    : st == "LISTENING"   ? QColor(0xFF,0xB7,0x66)
                                                          : QColor(0x8A,0x7A,0x6E));
                    net_hunt_table_->setItem(i, 3, si);
                    net_hunt_table_->setItem(i, 4, new QTableWidgetItem(lbl));
                }
                net_hunt_table_->setSortingEnabled(true);
            }
        }, Qt::QueuedConnection);
    }).detach();
}

} // namespace avdashboard
