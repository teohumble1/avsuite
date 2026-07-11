#include "main_window.hpp"
#include "av_quit_guard.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <ctime>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <QDateTime>
#include <QEvent>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QScrollBar>
#include <QSizePolicy>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include "avcore/detection_event.hpp"
#include "avcore/severity.hpp"
#include "avengine/engine.hpp"

namespace avdashboard {
namespace {

// ─── HistIcon ─────────────────────────────────────────────────────────────────
class HistIcon : public QWidget {
public:
    enum Type {
        Shield, Search, Sliders, Download, Trash, ChevronDown, ChevronRight,
        Clock, FileSearch, AlertTriangle, CheckCircle, XCircle, Activity,
        Zap, FolderSearch, Database, Cpu, Lock, Bug, TrendingUp, Layers,
        Filter, RefreshCw, Copy, ExternalLink, MoreHorizontal
    };
    HistIcon(Type t, int sz, QColor c, QWidget* parent = nullptr)
        : QWidget(parent), type_(t), color_(c) {
        setFixedSize(sz, sz);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }
    void setColor(QColor c) { color_ = c; update(); }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const double s = width() / 24.0;
        p.scale(s, s);
        QPen pen(color_, 1.65 / s);
        pen.setCapStyle(Qt::RoundCap);
        pen.setJoinStyle(Qt::RoundJoin);
        p.setPen(pen);
        p.setBrush(Qt::NoBrush);
        switch (type_) {
        case Shield: {
            QPainterPath pp;
            pp.moveTo(12,2); pp.lineTo(21,6); pp.lineTo(21,12);
            pp.cubicTo(21,17,16.5,21,12,22);
            pp.cubicTo(7.5,21,3,17,3,12);
            pp.lineTo(3,6); pp.closeSubpath();
            p.drawPath(pp); break;
        }
        case Search:
            p.drawEllipse(QPointF(11,11),7,7);
            p.drawLine(QPointF(16.5,16.5),QPointF(21,21));
            break;
        case Sliders:
            p.drawLine(QPointF(4,6),QPointF(20,6));
            p.drawLine(QPointF(4,12),QPointF(20,12));
            p.drawLine(QPointF(4,18),QPointF(20,18));
            p.drawEllipse(QPointF(8,6),2,2);
            p.drawEllipse(QPointF(16,12),2,2);
            p.drawEllipse(QPointF(10,18),2,2);
            break;
        case Download:
            p.drawLine(QPointF(12,3),QPointF(12,15));
            p.drawLine(QPointF(7,11),QPointF(12,16));
            p.drawLine(QPointF(17,11),QPointF(12,16));
            p.drawLine(QPointF(3,20),QPointF(21,20));
            break;
        case Trash:
            p.drawRoundedRect(QRectF(3,6,18,16),2,2);
            p.drawLine(QPointF(8,6),QPointF(8,3));
            p.drawLine(QPointF(8,3),QPointF(16,3));
            p.drawLine(QPointF(16,3),QPointF(16,6));
            p.drawLine(QPointF(1,6),QPointF(23,6));
            p.drawLine(QPointF(10,11),QPointF(10,17));
            p.drawLine(QPointF(14,11),QPointF(14,17));
            break;
        case ChevronDown:
            p.drawLine(QPointF(5,9),QPointF(12,16));
            p.drawLine(QPointF(12,16),QPointF(19,9));
            break;
        case ChevronRight:
            p.drawLine(QPointF(9,5),QPointF(16,12));
            p.drawLine(QPointF(16,12),QPointF(9,19));
            break;
        case Clock:
            p.drawEllipse(QPointF(12,12),9,9);
            p.drawLine(QPointF(12,7),QPointF(12,12));
            p.drawLine(QPointF(12,12),QPointF(15,14));
            break;
        case FileSearch: {
            QPainterPath pp;
            pp.moveTo(13,2); pp.lineTo(3,2); pp.lineTo(3,22);
            pp.lineTo(21,22); pp.lineTo(21,10); pp.closeSubpath();
            p.drawPath(pp);
            p.drawLine(QPointF(13,2),QPointF(13,10));
            p.drawLine(QPointF(13,10),QPointF(21,10));
            p.drawEllipse(QPointF(11,15),2.5,2.5);
            p.drawLine(QPointF(13,17),QPointF(15.5,19));
            break;
        }
        case AlertTriangle: {
            QPainterPath tri;
            tri.moveTo(12,2); tri.lineTo(22,20); tri.lineTo(2,20); tri.closeSubpath();
            p.drawPath(tri);
            p.drawLine(QPointF(12,9),QPointF(12,13));
            p.setBrush(color_);
            p.drawEllipse(QPointF(12,17),1,1);
            p.setBrush(Qt::NoBrush);
            break;
        }
        case CheckCircle:
            p.drawEllipse(QPointF(12,12),9,9);
            p.drawLine(QPointF(8,12),QPointF(11,15));
            p.drawLine(QPointF(11,15),QPointF(16,9));
            break;
        case XCircle:
            p.drawEllipse(QPointF(12,12),9,9);
            p.drawLine(QPointF(9,9),QPointF(15,15));
            p.drawLine(QPointF(15,9),QPointF(9,15));
            break;
        case Activity:
            p.drawLine(QPointF(3,12),QPointF(7,12));
            p.drawLine(QPointF(7,12),QPointF(9,5));
            p.drawLine(QPointF(9,5),QPointF(11,19));
            p.drawLine(QPointF(11,19),QPointF(13,9));
            p.drawLine(QPointF(13,9),QPointF(15,15));
            p.drawLine(QPointF(15,15),QPointF(17,12));
            p.drawLine(QPointF(17,12),QPointF(21,12));
            break;
        case Zap: {
            QPainterPath bolt;
            bolt.moveTo(13,2); bolt.lineTo(3,14); bolt.lineTo(11,14);
            bolt.lineTo(11,22); bolt.lineTo(21,10); bolt.lineTo(13,10);
            bolt.closeSubpath();
            p.drawPath(bolt); break;
        }
        case FolderSearch: {
            QPainterPath pp;
            pp.moveTo(22,20); pp.lineTo(2,20); pp.lineTo(2,8);
            pp.lineTo(9,8); pp.lineTo(11,5); pp.lineTo(22,5);
            pp.closeSubpath();
            p.drawPath(pp);
            p.drawEllipse(QPointF(12,13),3,3);
            p.drawLine(QPointF(14.5,15.5),QPointF(16.5,17.5));
            break;
        }
        case Database:
            p.drawEllipse(QRectF(3,3,18,6));
            p.drawLine(QPointF(3,6),QPointF(3,18));
            p.drawLine(QPointF(21,6),QPointF(21,18));
            p.drawEllipse(QRectF(3,15,18,6));
            p.drawLine(QPointF(3,9),QPointF(3,15));
            p.drawLine(QPointF(21,9),QPointF(21,15));
            { QPainterPath arc; arc.arcMoveTo(3,9,18,6,0); arc.arcTo(3,9,18,6,0,180); p.drawPath(arc); }
            break;
        case Cpu:
            p.drawRoundedRect(QRectF(7,7,10,10),2,2);
            p.drawLine(QPointF(9,7),QPointF(9,4)); p.drawLine(QPointF(12,7),QPointF(12,4)); p.drawLine(QPointF(15,7),QPointF(15,4));
            p.drawLine(QPointF(9,17),QPointF(9,20)); p.drawLine(QPointF(12,17),QPointF(12,20)); p.drawLine(QPointF(15,17),QPointF(15,20));
            p.drawLine(QPointF(7,9),QPointF(4,9)); p.drawLine(QPointF(7,12),QPointF(4,12)); p.drawLine(QPointF(7,15),QPointF(4,15));
            p.drawLine(QPointF(17,9),QPointF(20,9)); p.drawLine(QPointF(17,12),QPointF(20,12)); p.drawLine(QPointF(17,15),QPointF(20,15));
            break;
        case Lock:
            p.drawRoundedRect(QRectF(3,11,18,11),2,2);
            { QPainterPath arc; arc.arcMoveTo(8,3,8,10,0); arc.arcTo(8,3,8,10,0,180); p.drawPath(arc); }
            p.setBrush(color_);
            p.drawEllipse(QPointF(12,16),1.5,1.5);
            p.setBrush(Qt::NoBrush);
            break;
        case Bug: {
            p.drawEllipse(QPointF(12,13),5,6);
            p.drawEllipse(QPointF(12,7),3,3);
            p.drawLine(QPointF(9,10),QPointF(7,8));
            p.drawLine(QPointF(15,10),QPointF(17,8));
            p.drawLine(QPointF(7,13),QPointF(3,13));
            p.drawLine(QPointF(17,13),QPointF(21,13));
            p.drawLine(QPointF(7,17),QPointF(3,17));
            p.drawLine(QPointF(17,17),QPointF(21,17));
            break;
        }
        case TrendingUp:
            p.drawLine(QPointF(3,17),QPointF(9,11));
            p.drawLine(QPointF(9,11),QPointF(13,15));
            p.drawLine(QPointF(13,15),QPointF(21,7));
            p.drawLine(QPointF(17,7),QPointF(21,7));
            p.drawLine(QPointF(21,7),QPointF(21,11));
            break;
        case Layers:
            p.drawLine(QPointF(2,9),QPointF(12,5)); p.drawLine(QPointF(12,5),QPointF(22,9));
            p.drawLine(QPointF(2,9),QPointF(12,13)); p.drawLine(QPointF(12,13),QPointF(22,9));
            p.drawLine(QPointF(2,14),QPointF(12,18)); p.drawLine(QPointF(12,18),QPointF(22,14));
            p.drawLine(QPointF(2,19),QPointF(12,23)); p.drawLine(QPointF(12,23),QPointF(22,19));
            break;
        case Filter:
            p.drawLine(QPointF(4,4),QPointF(20,4));
            p.drawLine(QPointF(7,9),QPointF(17,9));
            p.drawLine(QPointF(10,14),QPointF(14,14));
            break;
        case RefreshCw: {
            QPainterPath arc;
            arc.arcMoveTo(3,3,18,18,60);
            arc.arcTo(3,3,18,18,60,-300);
            p.drawPath(arc);
            p.drawLine(QPointF(20,4),QPointF(20,8));
            p.drawLine(QPointF(20,8),QPointF(16,8));
            break;
        }
        case Copy: {
            p.drawRoundedRect(QRectF(9,3,12,14),2,2);
            p.drawRoundedRect(QRectF(3,7,12,14),2,2);
            break;
        }
        case ExternalLink:
            p.drawLine(QPointF(18,14),QPointF(18,20));
            p.drawLine(QPointF(18,20),QPointF(4,20));
            p.drawLine(QPointF(4,20),QPointF(4,6));
            p.drawLine(QPointF(4,6),QPointF(10,6));
            p.drawLine(QPointF(14,4),QPointF(20,4));
            p.drawLine(QPointF(20,4),QPointF(20,10));
            p.drawLine(QPointF(11,13),QPointF(20,4));
            break;
        case MoreHorizontal:
            p.setBrush(color_);
            p.drawEllipse(QPointF(5,12),1.2,1.2);
            p.drawEllipse(QPointF(12,12),1.2,1.2);
            p.drawEllipse(QPointF(19,12),1.2,1.2);
            p.setBrush(Qt::NoBrush);
            break;
        default: break;
        }
    }
private:
    Type type_; QColor color_;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
static QString SevToStr(avcore::Severity s) {
    switch (s) {
        case avcore::Severity::Malicious:  return "MALICIOUS";
        case avcore::Severity::Suspicious: return "SUSPICIOUS";
        default:                            return "INFO";
    }
}
static QColor SevColor(avcore::Severity s) {
    switch (s) {
        case avcore::Severity::Malicious:  return QColor(0xFF,0x5A,0x6A);
        case avcore::Severity::Suspicious: return QColor(0xFF,0xB0,0x20);
        default:                            return QColor(0x4A,0xDE,0x80);
    }
}
static QString FormatTs(const std::chrono::system_clock::time_point& tp) {
    auto t = std::chrono::system_clock::to_time_t(tp);
    char buf[32];
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    std::strftime(buf, sizeof(buf), "%H:%M:%S", &tm_buf);
    return QString::fromUtf8(buf);
}
static QString FormatDate(const std::chrono::system_clock::time_point& tp) {
    auto now = std::chrono::system_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::hours>(now - tp).count();
    if (diff < 24)  return "Today";
    if (diff < 48)  return "Yesterday";
    if (diff < 168) return "Last 7 Days";
    return "Last 30 Days";
}
static QString SourceLabel(const std::string& src) {
    if (src == "hash_signature") return "HASH SIG";
    if (src == "yara")           return "YARA";
    if (src == "pe_analyzer")    return "PE SCAN";
    if (src == "registry_scan")  return "REGISTRY";
    if (src == "behavior_engine")return "BEHAVIOR";
    if (src == "realtime")       return "REALTIME";
    return "SCAN";
}
static QColor SourceColor(const std::string& src) {
    if (src == "hash_signature") return QColor(0xFF,0x7A,0x00);
    if (src == "yara")           return QColor(0xFF,0x9B,0x3D);
    if (src == "pe_analyzer")    return QColor(0xFF,0xB7,0x66);
    if (src == "registry_scan")  return QColor(0xC0,0x84,0xFC);
    if (src == "behavior_engine")return QColor(0x4A,0xDE,0x80);
    if (src == "realtime")       return QColor(0x4A,0xDE,0x80);
    return QColor(0xFF,0x7A,0x00);
}

// ─── MiniBarChart ────────────────────────────────────────────────────────────
class MiniBarChart : public QWidget {
public:
    explicit MiniBarChart(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedHeight(72);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }
    void setData(const std::vector<avcore::DetectionEvent>& events) {
        // Group by day (last 7 days)
        threat_counts_.assign(7, 0);
        scan_counts_.assign(7, 1); // at least 1 scan per day shown
        auto now = std::chrono::system_clock::now();
        for (const auto& ev : events) {
            if (ev.rule_id.substr(0,4) == "SYS.") continue;
            auto diff = std::chrono::duration_cast<std::chrono::hours>(now - ev.timestamp).count();
            int day = static_cast<int>(diff / 24);
            if (day < 7) {
                int idx = 6 - day;
                if (ev.severity == avcore::Severity::Malicious ||
                    ev.severity == avcore::Severity::Suspicious)
                    ++threat_counts_[idx];
                ++scan_counts_[idx];
            }
        }
        update();
    }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const int W = width(), H = height();
        const int n = 7;
        const double bar_w = (W - 16.0) / n;

        int max_t = 1;
        for (int v : threat_counts_) if (v > max_t) max_t = v;
        int max_s = 1;
        for (int v : scan_counts_) if (v > max_s) max_s = v;

        // Draw threat area (red)
        QPainterPath threat_path;
        for (int i = 0; i < n; ++i) {
            double x = 8 + i * bar_w + bar_w / 2.0;
            double y = H - 6 - (static_cast<double>(threat_counts_[i]) / max_t) * (H - 16);
            if (i == 0) threat_path.moveTo(x, y);
            else        threat_path.lineTo(x, y);
        }
        {
            QPainterPath fill = threat_path;
            fill.lineTo(8 + 6 * bar_w + bar_w / 2.0, H - 6);
            fill.lineTo(8 + bar_w / 2.0, H - 6);
            fill.closeSubpath();
            p.setPen(Qt::NoPen);
            QLinearGradient g(0, 0, 0, H);
            g.setColorAt(0.0, QColor(255,90,106,100));
            g.setColorAt(1.0, QColor(255,90,106,0));
            p.setBrush(g);
            p.drawPath(fill);
        }
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(QColor(255,90,106,200), 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.drawPath(threat_path);

        // Draw scan area (orange, lighter)
        QPainterPath scan_path;
        for (int i = 0; i < n; ++i) {
            double x = 8 + i * bar_w + bar_w / 2.0;
            double y = H - 6 - (static_cast<double>(scan_counts_[i]) / max_s) * (H - 16) * 0.5;
            if (i == 0) scan_path.moveTo(x, y);
            else        scan_path.lineTo(x, y);
        }
        {
            QPainterPath fill = scan_path;
            fill.lineTo(8 + 6 * bar_w + bar_w / 2.0, H - 6);
            fill.lineTo(8 + bar_w / 2.0, H - 6);
            fill.closeSubpath();
            p.setPen(Qt::NoPen);
            QLinearGradient g(0, 0, 0, H);
            g.setColorAt(0.0, QColor(255,122,0,70));
            g.setColorAt(1.0, QColor(255,122,0,0));
            p.setBrush(g);
            p.drawPath(fill);
        }
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(QColor(255,122,0,160), 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.drawPath(scan_path);

        // Day labels
        const char* days[] = {"Mon","Tue","Wed","Thu","Fri","Sat","Sun"};
        p.setPen(QColor(0x4A,0x3B,0x30));
        p.setFont(QFont("Segoe UI", 7));
        for (int i = 0; i < n; ++i) {
            double x = 8 + i * bar_w;
            p.drawText(QRectF(x, H - 14, bar_w, 14), Qt::AlignCenter,
                       QString::fromUtf8(days[(QDate::currentDate().dayOfWeek() - 1 + i) % 7]));
        }
    }
private:
    std::vector<int> threat_counts_{7,0};
    std::vector<int> scan_counts_{7,1};
};

// ─── ClickableHeader ──────────────────────────────────────────────────────────
// Plain QWidget subclass (no Q_OBJECT) whose sizeHint() is layout-driven,
// fixing the QPushButton-as-container clipping bug.
class ClickableHeader : public QWidget {
public:
    explicit ClickableHeader(std::function<void()> cb, QWidget* parent = nullptr)
        : QWidget(parent), cb_(std::move(cb)) {
        setCursor(Qt::PointingHandCursor);
    }
    void setToggleCallback(std::function<void()> cb) { cb_ = std::move(cb); }
protected:
    void mousePressEvent(QMouseEvent* e) override {
        if (e->button() == Qt::LeftButton) { pressed_ = true; update(); }
        QWidget::mousePressEvent(e);
    }
    void mouseReleaseEvent(QMouseEvent* e) override {
        if (e->button() == Qt::LeftButton && pressed_) {
            pressed_ = false;
            if (rect().contains(e->pos()) && cb_) cb_();
            update();
        }
        QWidget::mouseReleaseEvent(e);
    }
    void enterEvent(QEnterEvent* e) override {
        hovered_ = true; update();
        QWidget::enterEvent(e);
    }
    void leaveEvent(QEvent* e) override {
        hovered_ = false; pressed_ = false; update();
        QWidget::leaveEvent(e);
    }
    void paintEvent(QPaintEvent* e) override {
        if (hovered_ || pressed_) {
            QPainter p(this);
            p.setRenderHint(QPainter::Antialiasing);
            p.setPen(Qt::NoPen);
            p.setBrush(QColor(255, 122, 0, pressed_ ? 22 : 12));
            p.drawRoundedRect(rect(), 12, 12);
        }
        QWidget::paintEvent(e);
    }
private:
    std::function<void()> cb_;
    bool hovered_ = false;
    bool pressed_ = false;
};

// ─── MakeScanCard ─────────────────────────────────────────────────────────────
static QWidget* MakeScanCard(const avcore::DetectionEvent& ev, QWidget* parent,
    std::function<void(const QString&, QPushButton*)> vt_cb = nullptr) {
    const QColor sev_color = SevColor(ev.severity);
    const QString sev_str = SevToStr(ev.severity);
    const QString src_label = SourceLabel(ev.source);
    const QColor src_color = SourceColor(ev.source);
    const QString ts_str = FormatTs(ev.timestamp);
    const QString date_str = FormatDate(ev.timestamp);
    const QString rule = QString::fromUtf8(ev.rule_id.c_str());
    const QString path = QString::fromUtf8(ev.target_path.c_str());
    const QString evid = QString::fromUtf8(ev.evidence.c_str());

    auto* card = new QFrame(parent);
    card->setFrameShape(QFrame::NoFrame);
    card->setStyleSheet(
        "QFrame#scan_card {"
        " background:#1C1108;"
        " border:1px solid rgba(255,170,90,26);"
        " border-radius:12px;"
        "}");
    card->setObjectName("scan_card");

    auto* card_l = new QVBoxLayout(card);
    card_l->setContentsMargins(0,0,0,0);
    card_l->setSpacing(0);

    // Header — ClickableHeader (QWidget subclass) so sizeHint() is layout-driven,
    // not QPushButton's broken sizeHint() that ignores child layout → clipping.
    auto* header = new ClickableHeader(nullptr, card);
    auto* header_l = new QHBoxLayout(header);
    header_l->setContentsMargins(16,12,16,12);
    header_l->setSpacing(10);

    // Status dot
    auto* dot = new QLabel(header);
    dot->setFixedSize(10,10);
    dot->setStyleSheet(QString(
        "background:%1; border-radius:5px;").arg(sev_color.name()));
    header_l->addWidget(dot);

    // Source badge
    auto* src_badge = new QLabel(src_label, header);
    src_badge->setStyleSheet(QString(
        "color:%1; background:rgba(%2,%3,%4,24);"
        " border:1px solid rgba(%2,%3,%4,50);"
        " border-radius:4px; padding:1px 6px;"
        " font-size:9pt; font-weight:700; font-family:Consolas,monospace;")
        .arg(src_color.name())
        .arg(src_color.red()).arg(src_color.green()).arg(src_color.blue()));
    header_l->addWidget(src_badge);

    // Rule name + date/time
    auto* name_col = new QVBoxLayout();
    name_col->setSpacing(2);
    QString display_rule = rule;
    if (display_rule.length() > 46)
        display_rule = display_rule.left(43) + "...";
    auto* name_lbl = new QLabel(display_rule, header);
    name_lbl->setToolTip(rule);
    name_lbl->setWordWrap(false);
    name_lbl->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    name_lbl->setStyleSheet(
        "color:#ECE4DA; font-size:10pt; font-weight:600;"
        " font-family:Consolas,monospace;");
    auto* date_row = new QHBoxLayout();
    date_row->setSpacing(8);
    auto* date_lbl = new QLabel(date_str + " \xc2\xb7 " + ts_str, header);
    date_lbl->setStyleSheet("color:#C7B6A2; font-size:9pt;");
    auto* dur_lbl = new QWidget(header);
    dur_lbl->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    {
        auto* cl = new QHBoxLayout(dur_lbl);
        cl->setContentsMargins(0,0,0,0);
        cl->setSpacing(3);
        cl->addWidget(new HistIcon(HistIcon::Clock, 11, QColor(0xC7,0xB6,0xA2), dur_lbl));
        auto* ct = new QLabel("0ms", dur_lbl);
        ct->setStyleSheet("color:#C7B6A2; font-size:9pt;");
        cl->addWidget(ct);
    }
    date_row->addWidget(date_lbl);
    date_row->addWidget(dur_lbl);
    date_row->addStretch();
    name_col->addWidget(name_lbl);
    name_col->addLayout(date_row);
    header_l->addLayout(name_col, 1);

    // Severity badge + chevron
    auto* sev_badge = new QLabel(sev_str, header);
    sev_badge->setStyleSheet(QString(
        "color:%1; background:rgba(%2,%3,%4,20);"
        " border:1px solid rgba(%2,%3,%4,38);"
        " border-radius:10px; padding:3px 10px;"
        " font-size:9pt; font-weight:600;")
        .arg(sev_color.name())
        .arg(sev_color.red()).arg(sev_color.green()).arg(sev_color.blue()));
    header_l->addWidget(sev_badge);

    auto* chevron = new HistIcon(HistIcon::ChevronDown, 15, QColor(0xC7,0xB6,0xA2), header);
    header_l->addWidget(chevron);
    card_l->addWidget(header);

    // Body (collapsed by default)
    auto* body = new QWidget(card);
    body->setVisible(false);
    body->setStyleSheet("background:transparent;");
    auto* body_l = new QVBoxLayout(body);
    body_l->setContentsMargins(16,0,16,14);
    body_l->setSpacing(6);

    // Separator
    auto* sep = new QFrame(body);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("background:rgba(255,170,90,25); border:none; max-height:1px;");
    sep->setFixedHeight(1);
    body_l->addWidget(sep);

    // Detection detail card
    auto* detail = new QFrame(body);
    detail->setStyleSheet(
        "QFrame { background:rgba(18,11,6,153);"
        " border:1px solid rgba(255,170,90,20); border-radius:8px; }");
    auto* detail_l = new QVBoxLayout(detail);
    detail_l->setContentsMargins(12,10,12,10);
    detail_l->setSpacing(5);

    auto makeRow = [&](const QString& label, const QString& value, QColor vc = QColor(0xE8,0xD5,0xC0)) {
        auto* row = new QHBoxLayout();
        row->setSpacing(8);
        auto* lbl = new QLabel(label, detail);
        lbl->setFixedWidth(64);
        lbl->setStyleSheet("color:#C7B6A2; font-size:9pt; font-family:Consolas,monospace; background:transparent;");
        auto* val = new QLabel(value, detail);
        val->setWordWrap(true);
        val->setStyleSheet(QString("color:%1; font-size:9pt; font-family:Consolas,monospace; background:transparent;")
            .arg(vc.name()));
        row->addWidget(lbl);
        row->addWidget(val, 1);
        detail_l->addLayout(row);
    };

    makeRow("Path", path.isEmpty() ? "(unknown)" : path);
    makeRow("Engine", QString::fromUtf8(ev.source.c_str()));
    if (!evid.isEmpty()) makeRow("Evidence", evid, QColor(0xFF,0xB7,0x66));
    if (ev.process_id) makeRow("PID", QString::number(ev.process_id), QColor(0xC0,0x84,0xFC));

    // VirusTotal button — only shown when a SHA-256 is extractable from evidence/path
    if (vt_cb) {
        static const QRegularExpression kSha256Re("[0-9a-fA-F]{64}");
        const QString search_text = evid + " " + path;
        auto hash_match = kSha256Re.match(search_text);
        if (hash_match.hasMatch()) {
            const QString hash = hash_match.captured(0);
            auto* vt_sep = new QFrame(detail);
            vt_sep->setFrameShape(QFrame::HLine);
            vt_sep->setStyleSheet("background:rgba(255,170,90,20); border:none; max-height:1px;");
            vt_sep->setFixedHeight(1);
            detail_l->addWidget(vt_sep);

            auto* vt_row_w = new QWidget(detail);
            vt_row_w->setStyleSheet("background:transparent;");
            auto* vt_row_l = new QHBoxLayout(vt_row_w);
            vt_row_l->setContentsMargins(0,0,0,0);
            vt_row_l->setSpacing(6);

            auto* vt_hash_lbl = new QLabel(hash.left(16) + "...", detail);
            vt_hash_lbl->setStyleSheet(
                "color:#8B7355; font-size:8.5pt; font-family:Consolas,monospace;"
                " background:transparent;");
            vt_row_l->addWidget(vt_hash_lbl, 1);

            auto* vt_btn_card = new QPushButton(detail);
            vt_btn_card->setFixedHeight(24);
            vt_btn_card->setStyleSheet(
                "QPushButton { background:rgba(255,122,0,20);"
                " border:1px solid rgba(255,122,0,50); border-radius:6px;"
                " color:#FF9B3D; font-size:8.5pt; padding:0 20px 0 8px; }"
                "QPushButton:hover { background:rgba(255,122,0,40); color:#fff; }"
                "QPushButton:disabled { color:rgba(255,255,255,25);"
                " border-color:rgba(255,255,255,10); background:transparent; }");
            {
                auto* vl = new QHBoxLayout(vt_btn_card);
                vl->setContentsMargins(8,0,8,0);
                vl->setSpacing(5);
                vl->addWidget(new HistIcon(HistIcon::ExternalLink, 11,
                                           QColor(0xFF,0x9B,0x3D), vt_btn_card));
                auto* vt_lbl = new QLabel("VirusTotal", vt_btn_card);
                vt_lbl->setStyleSheet(
                    "color:#FF9B3D; font-size:8.5pt; background:transparent;");
                vl->addWidget(vt_lbl);
            }
            QObject::connect(vt_btn_card, &QPushButton::clicked, vt_btn_card,
                [hash, vt_cb, vt_btn_card]() { vt_cb(hash, vt_btn_card); });
            vt_row_l->addWidget(vt_btn_card);
            detail_l->addWidget(vt_row_w);
        }
    }

    body_l->addWidget(detail);
    card_l->addWidget(body);

    // Wire toggle into header's callback
    header->setToggleCallback([card, body, chevron]() {
        const bool expanded = !body->isVisible();
        body->setVisible(expanded);
        card->setStyleSheet(expanded
            ? "QFrame#scan_card { background:#241708;"
              " border:1px solid rgba(255,122,0,64); border-radius:12px; }"
            : "QFrame#scan_card { background:#1C1108;"
              " border:1px solid rgba(255,170,90,26); border-radius:12px; }");
        chevron->setColor(expanded ? QColor(0xFF,0x7A,0x00) : QColor(0xC7,0xB6,0xA2));
    });

    return card;
}

// ─── MakeHdrBtn ──────────────────────────────────────────────────────────────
static QPushButton* MakeHdrBtn(HistIcon::Type ico, const QString& tip,
                                 QColor color, QWidget* parent) {
    auto* btn = new QPushButton(parent);
    btn->setFixedSize(32,32);
    btn->setToolTip(tip);
    btn->setStyleSheet(
        "QPushButton { background:#1C1108; border:1px solid rgba(255,170,90,26);"
        " border-radius:8px; }"
        "QPushButton:hover { background:rgba(255,122,0,30);"
        " border-color:rgba(255,122,0,80); }");
    auto* l = new QVBoxLayout(btn);
    l->setContentsMargins(7,7,7,7);
    l->addWidget(new HistIcon(ico, 16, color, btn));
    return btn;
}

} // namespace

// ─── BuildHistoryPage ─────────────────────────────────────────────────────────
QWidget* MainWindow::BuildHistoryPage() {
    auto* page = new QWidget();
    page->setStyleSheet("QWidget { background:#120B06; }");
    ArmQuitGuard(page);

    auto* root_l = new QVBoxLayout(page);
    root_l->setContentsMargins(0,0,0,0);
    root_l->setSpacing(0);

    // ═══════════════════════════════════════════════════════════════════════════
    // HEADER BAR
    // ═══════════════════════════════════════════════════════════════════════════
    auto* hdr = new QWidget(page);
    hdr->setFixedHeight(78);
    hdr->setStyleSheet(
        "QWidget { background:rgba(18,11,6,234);"
        " border-bottom:1px solid rgba(255,170,90,25); }");
    auto* hdr_l = new QHBoxLayout(hdr);
    hdr_l->setContentsMargins(20,0,16,0);
    hdr_l->setSpacing(12);

    // Logo + title
    auto* logo_box = new QFrame(hdr);
    logo_box->setFixedSize(32,32);
    logo_box->setStyleSheet(
        "QFrame { background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
        " stop:0 #FF7A00, stop:1 #FF7A00);"
        " border-radius:8px; border:none; }");
    auto* logo_box_l = new QVBoxLayout(logo_box);
    logo_box_l->setContentsMargins(7,7,7,7);
    logo_box_l->addWidget(new HistIcon(HistIcon::Shield, 16, Qt::white, logo_box));
    hdr_l->addWidget(logo_box);

    auto* title_col = new QVBoxLayout();
    title_col->setSpacing(1);
    auto* title_lbl = new QLabel(QString::fromUtf8("L\xe1\xbb\x8b"
                                                    "ch s\xe1\xbb\xad qu\xc3\xa9t"), hdr);
    title_lbl->setStyleSheet(
        "color:#ECE4DA; font-size:28px; font-weight:700; background:transparent;");
    auto* sub_lbl = new QLabel("Review detections, scans and security events", hdr);
    sub_lbl->setStyleSheet("color:#C7B6A2; font-size:9.5pt; background:transparent;");
    sub_lbl->setMinimumWidth(360);
    title_col->addWidget(title_lbl);
    title_col->addWidget(sub_lbl);
    hdr_l->addLayout(title_col);
    hdr_l->addStretch();

    // Scan buttons area
    auto makeScanBtn = [&](const QString& label, HistIcon::Type ico) -> QPushButton* {
        auto* btn = new QPushButton(hdr);
        btn->setFixedHeight(32);
        btn->setStyleSheet(
            "QPushButton { background:rgba(255,122,0,20);"
            " border:1px solid rgba(255,122,0,50);"
            " border-radius:8px; color:#C7B6A2;"
            " font-size:9.5pt; padding:0 10px 0 32px; text-align:left; }"
            "QPushButton:hover { background:rgba(255,122,0,40); color:#fff; }"
            "QPushButton:disabled { background:rgba(255,255,255,5);"
            " border-color:rgba(255,255,255,10); color:rgba(255,255,255,30); }");
        auto* icon = new HistIcon(ico, 13, QColor(0xFF,0x9B,0x3D), btn);
        icon->move(10, 9);
        btn->setText(label);
        return btn;
    };

    scan_folder_button_ = makeScanBtn(
        QString::fromUtf8("Qu\xc3\xa9t th\xc6\xb0 m\xe1\xbb\xa5" "c..."), HistIcon::FolderSearch);
    scan_files_button_ = makeScanBtn(
        QString::fromUtf8("Qu\xc3\xa9t file..."), HistIcon::FileSearch);
    scan_registry_button_ = makeScanBtn(
        QString::fromUtf8("Registry"), HistIcon::Database);
    scan_memory_button_ = makeScanBtn(
        QString::fromUtf8("B\xe1\xbb\x99 nh\xe1\xbb\x9b"), HistIcon::Cpu);
    scan_persistence_button_ = makeScanBtn(
        QString::fromUtf8("Persistence"), HistIcon::Lock);
    cancel_scan_button_ = new QPushButton(QString::fromUtf8("\xe2\x9c\x96 H\xe1\xbb\xa7y"), hdr);
    cancel_scan_button_->setFixedHeight(32);
    cancel_scan_button_->setVisible(false);
    cancel_scan_button_->setStyleSheet(
        "QPushButton { background:rgba(235,59,90,20);"
        " border:1px solid rgba(235,59,90,50);"
        " border-radius:8px; color:#FF5A6A; font-size:9.5pt; padding:0 10px; }"
        "QPushButton:hover { background:rgba(235,59,90,50); }");

    hdr_l->addWidget(scan_folder_button_);
    hdr_l->addWidget(scan_files_button_);
    hdr_l->addWidget(scan_registry_button_);
    hdr_l->addWidget(scan_memory_button_);
    hdr_l->addWidget(scan_persistence_button_);
    hdr_l->addWidget(cancel_scan_button_);
    hdr_l->addSpacing(8);

    // Search toggle
    auto* search_container = new QWidget(hdr);
    search_container->setFixedHeight(32);
    auto* search_l = new QHBoxLayout(search_container);
    search_l->setContentsMargins(0,0,0,0);
    search_l->setSpacing(0);
    auto* search_field = new QLineEdit(search_container);
    search_field->setPlaceholderText("Search scans...");
    search_field->setFixedHeight(32);
    search_field->setStyleSheet(
        "QLineEdit { background:#1C1108; border:1px solid rgba(255,170,90,46);"
        " border-radius:8px; padding:4px 12px 4px 32px;"
        " color:#ECE4DA; font-size:9.5pt; }"
        "QLineEdit:focus { border-color:rgba(255,122,0,120); }"
        "QLineEdit::placeholder { color:#33261A; }");
    search_field->setVisible(false);
    auto* search_ico = new HistIcon(HistIcon::Search, 14, QColor(0x4A,0x3B,0x30), search_field);
    search_ico->move(9, 8);
    search_l->addWidget(search_field);

    auto* search_btn = MakeHdrBtn(HistIcon::Search, "Search",
                                   QColor(0xC7,0xB6,0xA2), hdr);
    auto* filter_btn  = MakeHdrBtn(HistIcon::Sliders, "Filter",
                                    QColor(0xC7,0xB6,0xA2), hdr);
    auto* export_btn  = MakeHdrBtn(HistIcon::Download, "Export",
                                    QColor(0xC7,0xB6,0xA2), hdr);

    auto* clear_btn = new QPushButton(hdr);
    clear_btn->setFixedSize(100,32);
    clear_btn->setStyleSheet(
        "QPushButton { background:rgba(255,90,106,20);"
        " border:1px solid rgba(255,90,106,50); border-radius:8px;"
        " color:#FF5A6A; font-size:9.5pt; padding:0 8px; }"
        "QPushButton:hover { background:rgba(255,90,106,40); }");
    {
        auto* cl = new QHBoxLayout(clear_btn);
        cl->setContentsMargins(8,0,8,0); cl->setSpacing(5);
        cl->addWidget(new HistIcon(HistIcon::Trash, 13, QColor(0xFF,0x5A,0x6A), clear_btn));
        auto* ct = new QLabel(QString::fromUtf8("X\xc3\xb3" "a l\xe1\xbb\x8b"
                                                  "ch s\xe1\xbb\xad"), clear_btn);
        ct->setStyleSheet("color:#FF5A6A; font-size:9pt; background:transparent;");
        cl->addWidget(ct);
    }

    hdr_l->addWidget(search_container);
    hdr_l->addWidget(search_btn);
    hdr_l->addWidget(filter_btn);
    hdr_l->addWidget(export_btn);
    hdr_l->addWidget(clear_btn);
    root_l->addWidget(hdr);

    // Status + progress bar (hidden during idle)
    auto* prog_bar_widget = new QWidget(page);
    prog_bar_widget->setStyleSheet("QWidget { background:transparent; }");
    prog_bar_widget->setFixedHeight(30);
    prog_bar_widget->setVisible(false);
    auto* prog_l = new QHBoxLayout(prog_bar_widget);
    prog_l->setContentsMargins(20,4,20,4);
    prog_l->setSpacing(10);
    scan_progress_ = new QProgressBar(prog_bar_widget);
    scan_progress_->setRange(0,100);
    scan_progress_->setTextVisible(false);
    scan_progress_->setFixedHeight(4);
    scan_progress_->setStyleSheet(
        "QProgressBar { background:rgba(255,122,0,20); border-radius:2px; border:none; }"
        "QProgressBar::chunk { background:#FF7A00; border-radius:2px; }");
    scan_files_label_ = new QLabel(prog_bar_widget);
    scan_files_label_->setStyleSheet("color:rgba(199,182,162,0.55); font-size:8.5pt; background:transparent;");
    prog_l->addWidget(scan_progress_, 1);
    prog_l->addWidget(scan_files_label_);
    root_l->addWidget(prog_bar_widget);

    // Status label (shown below progress)
    status_label_ = new QLabel(QString::fromUtf8("S\xe1\xba\xb5n s\xc3\xa0ng."), page);
    status_label_->setObjectName("StatusLabel");
    status_label_->setFixedHeight(22);
    status_label_->setStyleSheet(
        "QLabel { color:rgba(199,182,162,0.6); font-size:9pt;"
        " padding-left:20px; background:transparent; }");
    root_l->addWidget(status_label_);

    // Connect prog_bar_widget visibility to scan_progress_ visibility
    // (AppendDetectionRow sets scan_progress_ visible during scans)
    scan_progress_->setVisible(true); // always inside the container
    scan_files_label_->setVisible(true);
    // We'll make prog_bar_widget visible during scan via scan_progress_ property trick:
    // Actually just let the existing OnScanFolderClicked handle scan_progress_
    // It calls scan_progress_->setVisible(true). We need prog_bar_widget to also show.
    // Connect scan_progress_ visibility to prog_bar_widget:
    connect(scan_progress_, &QProgressBar::valueChanged, prog_bar_widget,
            [prog_bar_widget, this](int) {
        prog_bar_widget->setVisible(true);
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // MAIN AREA (flex: left + right sidebar)
    // ═══════════════════════════════════════════════════════════════════════════
    auto* main_area = new QWidget(page);
    main_area->setStyleSheet("QWidget { background:transparent; }");
    auto* main_l = new QHBoxLayout(main_area);
    main_l->setContentsMargins(0,0,0,0);
    main_l->setSpacing(0);

    // ── LEFT CONTENT ──────────────────────────────────────────────────────────
    auto* left = new QWidget(main_area);
    left->setStyleSheet("QWidget { background:transparent; }");
    auto* left_l = new QVBoxLayout(left);
    left_l->setContentsMargins(20,12,12,8);
    left_l->setSpacing(8);

    // Filter tabs + view toggle
    auto* tabs_row = new QHBoxLayout();
    tabs_row->setSpacing(4);

    // Time filter state — heap-allocated so lambdas can outlive BuildHistoryPage()
    int* active_filter_idx = new int(0);
    const char* filter_labels[] = {"All", "Today", "Yesterday", "Last 7 Days", "Last 30 Days"};
    auto filter_btns = std::make_shared<std::vector<QPushButton*>>();

    auto* view_cards_btn = new QPushButton(left);
    auto* view_table_btn = new QPushButton(left);
    auto* cards_scroll_widget = new QWidget(left);

    // shared_ptr so the closure stays valid after BuildHistoryPage() returns
    auto refresh_fn = std::make_shared<std::function<void()>>(nullptr);

    static const QString kActiveTab =
        "QPushButton { background:rgba(255,122,0,38);"
        " border:1px solid rgba(255,122,0,64); border-radius:8px;"
        " color:#FF7A00; font-size:9.5pt; padding:0 10px; }";
    static const QString kInactiveTab =
        "QPushButton { background:transparent; border:1px solid transparent;"
        " border-radius:8px; color:#C7B6A2; font-size:9.5pt; padding:0 10px; }"
        "QPushButton:hover { background:rgba(255,122,0,15); }";

    for (int i = 0; i < 5; ++i) {
        auto* fb = new QPushButton(QString::fromUtf8(filter_labels[i]), left);
        fb->setFixedHeight(28);
        fb->setStyleSheet(kInactiveTab);
        filter_btns->push_back(fb);
        tabs_row->addWidget(fb);

        connect(fb, &QPushButton::clicked, fb,
                [i, active_filter_idx, filter_btns, refresh_fn]() {
            *active_filter_idx = i;
            for (int j = 0; j < (int)filter_btns->size(); ++j)
                (*filter_btns)[j]->setStyleSheet(j == i ? kActiveTab : kInactiveTab);
            if (*refresh_fn) (*refresh_fn)();
        });
    }
    (*filter_btns)[0]->setStyleSheet(kActiveTab);

    tabs_row->addStretch();

    // View mode toggle
    auto* view_toggle = new QFrame(left);
    view_toggle->setStyleSheet(
        "QFrame { background:#1C1108; border:1px solid rgba(255,170,90,26); border-radius:8px; }");
    auto* vt_l = new QHBoxLayout(view_toggle);
    vt_l->setContentsMargins(2,2,2,2);
    vt_l->setSpacing(2);

    view_cards_btn->setFixedSize(30,24);
    view_cards_btn->setStyleSheet(
        "QPushButton { background:rgba(255,122,0,38); border:none;"
        " border-radius:6px; color:#FF7A00; }"
        "QPushButton:hover { background:rgba(255,122,0,60); }");
    view_cards_btn->setToolTip("Card View");
    {
        auto* vl = new QVBoxLayout(view_cards_btn);
        vl->setContentsMargins(6,4,6,4);
        vl->addWidget(new HistIcon(HistIcon::Layers, 14, QColor(0xFF,0x7A,0x00), view_cards_btn));
    }
    view_table_btn->setFixedSize(30,24);
    view_table_btn->setStyleSheet(
        "QPushButton { background:transparent; border:none; border-radius:6px; color:#C7B6A2; }"
        "QPushButton:hover { background:rgba(255,122,0,20); }");
    view_table_btn->setToolTip("Table View");
    {
        auto* vl = new QVBoxLayout(view_table_btn);
        vl->setContentsMargins(6,4,6,4);
        vl->addWidget(new HistIcon(HistIcon::Filter, 14, QColor(0xC7,0xB6,0xA2), view_table_btn));
    }
    vt_l->addWidget(view_cards_btn);
    vt_l->addWidget(view_table_btn);
    tabs_row->addWidget(view_toggle);
    left_l->addLayout(tabs_row);

    // Stacked widget: cards view | table view
    auto* view_stack = new QStackedWidget(left);
    view_stack->setStyleSheet("QStackedWidget { background:transparent; }");

    // PAGE 0: Cards view
    auto* cards_scroll = new QScrollArea(view_stack);
    cards_scroll->setWidgetResizable(true);
    cards_scroll->setFrameShape(QFrame::NoFrame);
    cards_scroll->setStyleSheet(
        "QScrollArea { background:transparent; border:none; }"
        "QScrollBar:vertical { background:transparent; width:4px; margin:0; }"
        "QScrollBar::handle:vertical { background:rgba(255,170,90,50); border-radius:2px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }");
    cards_scroll_widget->setStyleSheet("background:transparent;");
    auto* cards_l = new QVBoxLayout(cards_scroll_widget);
    cards_l->setContentsMargins(0,0,0,0);
    cards_l->setSpacing(8);
    cards_l->addStretch();
    cards_scroll->setWidget(cards_scroll_widget);
    view_stack->addWidget(cards_scroll);

    // VT callback passed into each card — captures this (safe: MainWindow owns page)
    auto vt_cb = std::function<void(const QString&, QPushButton*)>(
        [this](const QString& sha, QPushButton* btn) {
            btn->setEnabled(false);
            btn->setText("...");
            std::thread([this, sha, btn] {
                const std::string result = engine_->LookupVirusTotal(sha.toStdString());
                if (AppQuitting().load()) return;
                QMetaObject::invokeMethod(this, [this, result, btn] {
                    if (btn) {
                        btn->setEnabled(true);
                        btn->setText("VirusTotal");
                    }
                    QMessageBox::information(this, "VirusTotal",
                        QString::fromUtf8(result.c_str()));
                }, Qt::QueuedConnection);
            }).detach();
        });

    // Assign refresh_fn — captured pointers are Qt-managed widgets (valid as long as page exists)
    *refresh_fn = [this, cards_l, cards_scroll_widget, active_filter_idx, vt_cb]() {
        static const QString kDateFilter[] =
            {"", "Today", "Yesterday", "Last 7 Days", "Last 30 Days"};
        while (cards_l->count() > 0) {
            auto* item = cards_l->takeAt(0);
            if (item->widget()) item->widget()->deleteLater();
            delete item;
        }
        const auto detections = engine_->RecentDetections(500);
        bool any = false;
        for (auto it = detections.rbegin(); it != detections.rend(); ++it) {
            const auto& ev = *it;
            if (ev.rule_id.substr(0,4) == "SYS.") continue;
            if (*active_filter_idx > 0) {
                if (FormatDate(ev.timestamp) != kDateFilter[*active_filter_idx]) continue;
            }
            cards_l->addWidget(MakeScanCard(ev, cards_scroll_widget, vt_cb));
            any = true;
        }
        if (!any) {
            // Empty state
            auto* es = new QWidget(cards_scroll_widget);
            auto* es_l = new QVBoxLayout(es);
            es_l->setAlignment(Qt::AlignCenter);
            es_l->setSpacing(12);
            auto* es_icon_box = new QFrame(es);
            es_icon_box->setFixedSize(72,72);
            es_icon_box->setStyleSheet(
                "QFrame { background:rgba(255,122,0,23);"
                " border:1px solid rgba(255,122,0,51); border-radius:18px; }");
            auto* es_icon_box_l = new QVBoxLayout(es_icon_box);
            es_icon_box_l->setContentsMargins(18,18,18,18);
            es_icon_box_l->addWidget(new HistIcon(HistIcon::Shield,34,QColor(0xFF,0x7A,0x00),es_icon_box));
            es_l->addWidget(es_icon_box, 0, Qt::AlignCenter);
            auto* es_title = new QLabel("No scan history yet", es);
            es_title->setStyleSheet(
                "color:#ECE4DA; font-size:13pt; font-weight:600; background:transparent;");
            es_title->setAlignment(Qt::AlignCenter);
            auto* es_sub = new QLabel("Run your first scan to start monitoring threats.", es);
            es_sub->setStyleSheet("color:#C7B6A2; font-size:10pt; background:transparent;");
            es_sub->setAlignment(Qt::AlignCenter);
            es_l->addWidget(es_title);
            es_l->addWidget(es_sub);
            cards_l->addWidget(es, 0, Qt::AlignCenter);
        }
        cards_l->addStretch();
    };

    // PAGE 1: Table view
    detections_table_ = new QTableWidget(0, 5, view_stack);
    detections_table_->setHorizontalHeaderLabels({
        QString::fromUtf8("Th\xe1\xbb\x9d"
                          "i gian"),
        QString::fromUtf8("M\xe1\xbb\xa9"
                          "c \xc4\x91\xe1\xbb\x99"),
        "Rule",
        QString::fromUtf8("\xc4\x90\xc6\xb0\xe1\xbb\x9d"
                          "ng d\xe1\xba\xabn"),
        QString::fromUtf8("Chi ti\xe1\xba\xbft")
    });
    {
        auto* hh = detections_table_->horizontalHeader();
        hh->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        hh->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        hh->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        hh->setSectionResizeMode(3, QHeaderView::Stretch);
        hh->setSectionResizeMode(4, QHeaderView::Interactive);
        hh->resizeSection(4, 300);
    }
    detections_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    detections_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    detections_table_->setAlternatingRowColors(false);
    detections_table_->verticalHeader()->setVisible(false);
    detections_table_->setShowGrid(false);
    detections_table_->setStyleSheet(
        "QTableWidget { background:#1C1108; border:1px solid rgba(255,170,90,26);"
        " border-radius:12px; gridline-color:transparent; color:#ECE4DA;"
        " font-size:9.5pt; selection-background-color:rgba(255,122,0,30); }"
        "QTableWidget::item { padding:6px 8px; border-bottom:1px solid rgba(255,170,90,15); }"
        "QTableWidget::item:selected { background:rgba(255,122,0,30); color:#fff; }"
        "QHeaderView::section { background:rgba(26,18,12,255);"
        " color:#8B7355; border:none; border-bottom:1px solid rgba(255,170,90,36);"
        " padding:6px 8px; font-size:8.5pt; font-weight:700; letter-spacing:0.8px; }"
        "QScrollBar:vertical { background:transparent; width:4px; margin:0; }"
        "QScrollBar::handle:vertical { background:rgba(255,170,90,50); border-radius:2px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }");
    view_stack->addWidget(detections_table_);

    left_l->addWidget(view_stack, 1);

    // VT lookup row
    auto* vt_row = new QHBoxLayout();
    auto* vt_btn = new QPushButton(
        QString::fromUtf8("  Tra c\xe1\xbb\xa9u VirusTotal"), left);
    vt_btn->setFixedHeight(28);
    vt_btn->setStyleSheet(
        "QPushButton { background:rgba(255,122,0,15);"
        " border:1px solid rgba(255,122,0,40); border-radius:8px;"
        " color:#FF9B3D; font-size:9pt; padding:0 12px 0 28px; }"
        "QPushButton:hover { background:rgba(255,122,0,35); color:#fff; }"
        "QPushButton:disabled { color:rgba(255,255,255,25); border-color:rgba(255,255,255,10);"
        " background:transparent; }");
    {
        auto* vi = new HistIcon(HistIcon::ExternalLink, 13, QColor(0xFF,0x9B,0x3D), vt_btn);
        vi->move(9, 7);
    }
    vt_row->addWidget(vt_btn);
    vt_row->addStretch();
    left_l->addLayout(vt_row);
    main_l->addWidget(left, 1);

    // ── RIGHT SIDEBAR (288px) ──────────────────────────────────────────────────
    auto* right = new QWidget(main_area);
    right->setFixedWidth(288);
    right->setStyleSheet(
        "QWidget { background:transparent;"
        " border-left:1px solid rgba(255,170,90,18); }");
    auto* right_scroll = new QScrollArea(right);
    right_scroll->setWidgetResizable(true);
    right_scroll->setFrameShape(QFrame::NoFrame);
    right_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    right_scroll->setStyleSheet(
        "QScrollArea { background:transparent; border:none; }"
        "QScrollBar:vertical { background:transparent; width:3px; }"
        "QScrollBar::handle:vertical { background:rgba(255,170,90,40); border-radius:1px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }");
    auto* rp = new QWidget(right_scroll);
    rp->setStyleSheet("background:transparent;");
    auto* rp_l = new QVBoxLayout(rp);
    rp_l->setContentsMargins(12,12,12,12);
    rp_l->setSpacing(10);

    auto makeCard = [&](const QString& header, HistIcon::Type ico,
                         QColor ic_color, QColor border_tint) -> QPair<QFrame*, QVBoxLayout*> {
        auto* card = new QFrame(rp);
        card->setStyleSheet(QString(
            "QFrame { background:rgba(26,18,12,230);"
            " border:1px solid rgba(%1,%2,%3,36); border-radius:12px; }")
            .arg(border_tint.red()).arg(border_tint.green()).arg(border_tint.blue()));
        auto* l = new QVBoxLayout(card);
        l->setContentsMargins(12,10,12,10);
        l->setSpacing(8);
        auto* hdr_row = new QHBoxLayout();
        hdr_row->setSpacing(6);
        hdr_row->addWidget(new HistIcon(ico, 12, ic_color, card));
        auto* lbl = new QLabel(header, card);
        lbl->setStyleSheet(
            "color:#8B7355; font-size:8.5pt; font-weight:700;"
            " letter-spacing:1px; background:transparent;");
        hdr_row->addWidget(lbl);
        hdr_row->addStretch();
        l->addLayout(hdr_row);
        return {card, l};
    };

    // Detection Activity chart card
    {
        auto [chart_card, cl] = makeCard("DETECTION ACTIVITY",
                                          HistIcon::TrendingUp, QColor(0xFF,0x7A,0x00),
                                          QColor(0xFF,0xAA,0x5A));
        auto* chart = new MiniBarChart(chart_card);
        chart->setData(engine_->RecentDetections(1000));
        cl->addWidget(chart);
        // Legend
        auto* legend = new QHBoxLayout();
        legend->setSpacing(12);
        auto* l1_row = new QHBoxLayout(); l1_row->setSpacing(4);
        auto* l1_bar = new QFrame(chart_card); l1_bar->setFixedSize(14,2);
        l1_bar->setStyleSheet("QFrame { background:#FF5A6A; border:none; border-radius:1px; }");
        auto* l1_txt = new QLabel("Threats", chart_card);
        l1_txt->setStyleSheet("color:#C7B6A2; font-size:8.5pt; background:transparent;");
        l1_row->addWidget(l1_bar); l1_row->addWidget(l1_txt);
        auto* l2_row = new QHBoxLayout(); l2_row->setSpacing(4);
        auto* l2_bar = new QFrame(chart_card); l2_bar->setFixedSize(14,2);
        l2_bar->setStyleSheet("QFrame { background:#FF7A00; border:none; border-radius:1px; }");
        auto* l2_txt = new QLabel("Scans", chart_card);
        l2_txt->setStyleSheet("color:#C7B6A2; font-size:8.5pt; background:transparent;");
        l2_row->addWidget(l2_bar); l2_row->addWidget(l2_txt);
        legend->addLayout(l1_row); legend->addLayout(l2_row); legend->addStretch();
        cl->addLayout(legend);
        rp_l->addWidget(chart_card);
    }

    // Stats 2x2 grid
    {
        const auto all = engine_->RecentDetections(10000);
        int total = static_cast<int>(all.size());
        int malicious = 0, suspicious = 0;
        for (const auto& ev : all) {
            if (ev.severity == avcore::Severity::Malicious) ++malicious;
            else if (ev.severity == avcore::Severity::Suspicious) ++suspicious;
        }
        int info = total - malicious - suspicious;

        auto makeStatCard = [&](const QString& label, const QString& value,
                                 const QString& sub, QColor color,
                                 HistIcon::Type ico) -> QWidget* {
            auto* card = new QFrame(rp);
            card->setStyleSheet(
                "QFrame { background:rgba(26,18,12,230);"
                " border:1px solid rgba(255,170,90,26); border-radius:10px; }");
            auto* l = new QHBoxLayout(card);
            l->setContentsMargins(10,8,10,8);
            l->setSpacing(8);
            auto* ico_box = new QFrame(card);
            ico_box->setFixedSize(30,30);
            ico_box->setStyleSheet(QString(
                "QFrame { background:rgba(%1,%2,%3,21);"
                " border:1px solid rgba(%1,%2,%3,38); border-radius:8px; }")
                .arg(color.red()).arg(color.green()).arg(color.blue()));
            auto* ib_l = new QVBoxLayout(ico_box);
            ib_l->setContentsMargins(7,7,7,7);
            ib_l->addWidget(new HistIcon(ico, 14, color, ico_box));
            l->addWidget(ico_box);
            auto* tc = new QVBoxLayout();
            tc->setSpacing(1);
            auto* ll = new QLabel(label, card);
            ll->setStyleSheet("color:#C7B6A2; font-size:8.5pt; background:transparent;");
            auto* vl = new QLabel(value, card);
            vl->setStyleSheet(
                "color:#ECE4DA; font-size:14pt; font-weight:700;"
                " font-family:Consolas,monospace; background:transparent;");
            auto* sl = new QLabel(sub, card);
            sl->setStyleSheet("color:#8B7355; font-size:8pt; background:transparent;");
            tc->addWidget(ll); tc->addWidget(vl); tc->addWidget(sl);
            l->addLayout(tc, 1);
            return card;
        };

        auto* grid_row1 = new QHBoxLayout(); grid_row1->setSpacing(6);
        auto* grid_row2 = new QHBoxLayout(); grid_row2->setSpacing(6);
        grid_row1->addWidget(makeStatCard("Total Scans", QString::number(total),
                                           "All time", QColor(0xFF,0x7A,0x00), HistIcon::FileSearch));
        grid_row1->addWidget(makeStatCard("Threats", QString::number(malicious),
                                           "Quarantined", QColor(0xFF,0x5A,0x6A), HistIcon::Bug));
        grid_row2->addWidget(makeStatCard("Suspicious", QString::number(suspicious),
                                           "Flagged", QColor(0xFF,0xB0,0x20), HistIcon::AlertTriangle));
        grid_row2->addWidget(makeStatCard("Info/Clean", QString::number(info),
                                           "Pass rate", QColor(0x4A,0xDE,0x80), HistIcon::CheckCircle));
        rp_l->addLayout(grid_row1);
        rp_l->addLayout(grid_row2);
    }

    // Recent Threats card
    {
        auto [threats_card, tl] = makeCard("RECENT THREATS",
                                            HistIcon::AlertTriangle, QColor(0xFF,0x5A,0x6A),
                                            QColor(0xFF,0x5A,0x6A));
        const auto recent = engine_->RecentDetections(10);
        int shown = 0;
        for (const auto& ev : recent) {
            if (ev.rule_id.substr(0,4) == "SYS.") continue;
            if (ev.severity != avcore::Severity::Malicious &&
                ev.severity != avcore::Severity::Suspicious) continue;
            if (shown++ >= 5) break;
            const QColor sev_c = SevColor(ev.severity);
            auto* item = new QFrame(threats_card);
            item->setStyleSheet(
                "QFrame { background:#120B06;"
                " border:1px solid rgba(255,170,90,18); border-radius:8px; }");
            auto* il = new QHBoxLayout(item);
            il->setContentsMargins(10,7,10,7);
            il->setSpacing(8);
            auto* dot = new QLabel(item);
            dot->setFixedSize(6,6);
            dot->setStyleSheet(QString(
                "QLabel { background:%1; border-radius:3px; border:none; }").arg(sev_c.name()));
            auto* txt_col = new QVBoxLayout();
            txt_col->setSpacing(1);
            auto* nm = new QLabel(QString::fromUtf8(ev.rule_id.c_str()), item);
            nm->setStyleSheet(
                "color:#ECE4DA; font-size:9pt; font-family:Consolas,monospace;"
                " background:transparent;");
            nm->setMaximumWidth(170);
            auto* sv = new QLabel(SevToStr(ev.severity), item);
            sv->setStyleSheet(QString("color:%1; font-size:8.5pt; background:transparent;")
                .arg(sev_c.name()));
            txt_col->addWidget(nm); txt_col->addWidget(sv);
            auto* ts = new QLabel(FormatTs(ev.timestamp), item);
            ts->setStyleSheet("color:#8B7355; font-size:8.5pt; background:transparent;");
            il->addWidget(dot); il->addLayout(txt_col, 1); il->addWidget(ts);
            tl->addWidget(item);
        }
        if (shown == 0) {
            auto* lbl = new QLabel("No threats detected", threats_card);
            lbl->setStyleSheet("color:#8B7355; font-size:9.5pt; background:transparent;");
            lbl->setAlignment(Qt::AlignCenter);
            tl->addWidget(lbl);
        }
        rp_l->addWidget(threats_card);
    }

    rp_l->addStretch();
    right_scroll->setWidget(rp);
    auto* right_l = new QVBoxLayout(right);
    right_l->setContentsMargins(0,0,0,0);
    right_l->addWidget(right_scroll);
    main_l->addWidget(right);
    root_l->addWidget(main_area, 1);

    // ═══════════════════════════════════════════════════════════════════════════
    // BOTTOM: Security Activity Feed
    // ═══════════════════════════════════════════════════════════════════════════
    auto* feed = new QWidget(page);
    feed->setFixedHeight(168);
    feed->setStyleSheet(
        "QWidget { background:rgba(18,11,6,178);"
        " border-top:1px solid rgba(255,170,90,25); }");
    auto* feed_l = new QVBoxLayout(feed);
    feed_l->setContentsMargins(20,10,20,10);
    feed_l->setSpacing(8);

    // Feed header
    auto* feed_hdr = new QHBoxLayout();
    feed_hdr->setSpacing(8);
    feed_hdr->addWidget(new HistIcon(HistIcon::Activity, 13, QColor(0xFF,0x7A,0x00), feed));
    auto* feed_title = new QLabel("SECURITY ACTIVITY FEED", feed);
    feed_title->setStyleSheet(
        "color:#8B7355; font-size:9pt; font-weight:700;"
        " letter-spacing:1px; background:transparent;");
    feed_hdr->addWidget(feed_title);
    auto* live_badge = new QLabel("LIVE", feed);
    live_badge->setStyleSheet(
        "QLabel { background:rgba(255,90,106,38); color:#FF5A6A;"
        " border:none; border-radius:8px; padding:2px 7px;"
        " font-size:8pt; font-weight:700; font-family:Consolas,monospace; }");
    feed_hdr->addWidget(live_badge);
    feed_hdr->addStretch();
    auto* refresh_btn = new QPushButton(feed);
    refresh_btn->setFixedSize(26,22);
    refresh_btn->setStyleSheet(
        "QPushButton { background:transparent; border:none; border-radius:5px; }"
        "QPushButton:hover { background:rgba(255,122,0,20); }");
    {
        auto* rl = new QVBoxLayout(refresh_btn);
        rl->setContentsMargins(5,4,5,4);
        rl->addWidget(new HistIcon(HistIcon::RefreshCw, 12, QColor(0xC7,0xB6,0xA2), refresh_btn));
    }
    feed_hdr->addWidget(refresh_btn);
    feed_l->addLayout(feed_hdr);

    // 3-column activity grid
    auto* activity_grid = new QHBoxLayout();
    activity_grid->setSpacing(6);

    const auto activity_events = engine_->RecentDetections(12);
    int shown = 0;
    for (const auto& ev : activity_events) {
        if (shown >= 6) break;
        const QColor sev_c = SevColor(ev.severity);
        const QString bg_str = QString("rgba(%1,%2,%3,20)")
            .arg(sev_c.red()).arg(sev_c.green()).arg(sev_c.blue());
        const QString border_str = QString("rgba(%1,%2,%3,38)")
            .arg(sev_c.red()).arg(sev_c.green()).arg(sev_c.blue());

        auto* row = new QFrame(feed);
        row->setStyleSheet(QString(
            "QFrame { background:#1C1108;"
            " border:1px solid rgba(255,170,90,18); border-radius:8px; }"));
        auto* row_l = new QHBoxLayout(row);
        row_l->setContentsMargins(10,8,10,8);
        row_l->setSpacing(8);

        // Icon box
        auto* ico_box = new QFrame(row);
        ico_box->setFixedSize(24,24);
        ico_box->setStyleSheet(QString(
            "QFrame { background:%1; border:1px solid %2; border-radius:6px; }")
            .arg(bg_str, border_str));
        auto* ib_l = new QVBoxLayout(ico_box);
        ib_l->setContentsMargins(4,4,4,4);
        HistIcon::Type ico_type = HistIcon::Zap;
        if (ev.source == "registry_scan") ico_type = HistIcon::Database;
        else if (ev.rule_id == "SYS.QUARANTINED") ico_type = HistIcon::Lock;
        else if (ev.source == "behavior_engine") ico_type = HistIcon::Activity;
        ib_l->addWidget(new HistIcon(ico_type, 14, sev_c, ico_box));
        row_l->addWidget(ico_box, 0, Qt::AlignTop);

        auto* text_col = new QVBoxLayout();
        text_col->setSpacing(2);
        auto* rule_lbl = new QLabel(QString::fromUtf8(ev.rule_id.c_str()), row);
        rule_lbl->setWordWrap(true);
        rule_lbl->setStyleSheet("color:#ECE4DA; font-size:9pt; background:transparent;");
        auto path_short = QString::fromUtf8(ev.target_path.c_str());
        if (path_short.length() > 40) path_short = "..." + path_short.right(37);
        auto* path_lbl = new QLabel(path_short, row);
        path_lbl->setStyleSheet("color:#8B7355; font-size:8.5pt; background:transparent;");
        text_col->addWidget(rule_lbl);
        text_col->addWidget(path_lbl);
        auto* ts_lbl = new QLabel(FormatTs(ev.timestamp), row);
        ts_lbl->setStyleSheet("color:#33261A; font-size:8pt; background:transparent;");
        ts_lbl->setAlignment(Qt::AlignTop | Qt::AlignRight);
        row_l->addLayout(text_col, 1);
        row_l->addWidget(ts_lbl, 0, Qt::AlignTop);

        activity_grid->addWidget(row, 1);
        ++shown;
    }
    while (shown++ < 3) activity_grid->addStretch(1);
    feed_l->addLayout(activity_grid);
    root_l->addWidget(feed);

    // ═══════════════════════════════════════════════════════════════════════════
    // VIEW MODE WIRING
    // ═══════════════════════════════════════════════════════════════════════════
    connect(view_cards_btn, &QPushButton::clicked, this,
            [view_stack, view_cards_btn, view_table_btn, refresh_fn]() {
        view_stack->setCurrentIndex(0);
        view_cards_btn->setStyleSheet(
            "QPushButton { background:rgba(255,122,0,38); border:none;"
            " border-radius:6px; color:#FF7A00; }");
        view_table_btn->setStyleSheet(
            "QPushButton { background:transparent; border:none;"
            " border-radius:6px; color:#C7B6A2; }"
            "QPushButton:hover { background:rgba(255,122,0,20); }");
        if (*refresh_fn) (*refresh_fn)();
    });
    connect(view_table_btn, &QPushButton::clicked, this, [view_stack, view_cards_btn, view_table_btn]() {
        view_stack->setCurrentIndex(1);
        view_table_btn->setStyleSheet(
            "QPushButton { background:rgba(255,122,0,38); border:none;"
            " border-radius:6px; color:#FF7A00; }");
        view_cards_btn->setStyleSheet(
            "QPushButton { background:transparent; border:none;"
            " border-radius:6px; color:#C7B6A2; }"
            "QPushButton:hover { background:rgba(255,122,0,20); }");
    });

    // Search filter — applies to table view
    connect(search_btn, &QPushButton::clicked, this,
            [search_field, search_btn](){ search_field->setVisible(!search_field->isVisible()); });
    connect(search_field, &QLineEdit::textChanged, this,
            [this](const QString& text) {
        const QString lower = text.toLower();
        for (int r = 0; r < detections_table_->rowCount(); ++r) {
            bool match = text.isEmpty();
            if (!match) {
                for (int c = 0; c < detections_table_->columnCount(); ++c) {
                    auto* item = detections_table_->item(r, c);
                    if (item && item->text().toLower().contains(lower)) { match = true; break; }
                }
            }
            detections_table_->setRowHidden(r, !match);
        }
    });

    // VT lookup (table view) — searches selected row for 64-char hex hash
    connect(vt_btn, &QPushButton::clicked, this, [this, vt_btn] {
        const auto selected = detections_table_->selectionModel()->selectedRows();
        if (selected.isEmpty()) {
            QMessageBox::information(this, "VirusTotal",
                QString::fromUtf8("Ch\xe1\xbb\x8dn m\xe1\xbb\x99t d\xc3\xb2ng trong b\xe1\xba\xa3ng"
                                  " (ch\xe1\xbb\x8f \xc4\x91\xe1\xbb\x8bnh d\xe1\xba\xa1ng b\xe1\xba\xa3ng)."));
            return;
        }
        static const QRegularExpression re("[0-9a-fA-F]{64}");
        QString sha256;
        const int row = selected.first().row();
        for (int col = 0; col < detections_table_->columnCount(); ++col) {
            auto* item = detections_table_->item(row, col);
            if (!item) continue;
            auto m = re.match(item->text());
            if (m.hasMatch()) { sha256 = m.captured(0); break; }
        }
        if (sha256.isEmpty()) {
            QMessageBox::information(this, "VirusTotal",
                QString::fromUtf8("Kh\xc3\xb4ng t\xc3\xacm th\xe1\xba\xa5y SHA-256 trong d\xc3\xb2ng n\xc3\xa0"
                                  "y.\nCh\xe1\xbb\x89 h\xe1\xbb\x97 tr\xe1\xbb\xa3 hash_signature detection.\n"
                                  "V\xe1\xbb\x9bi YARA/behavior: m\xe1\xbb\x9f r\xe1\xbb\x99ng card v\xc3\xa0"
                                  " d\xc3\xb9ng n\xc3\xbat VirusTotal trong card."));
            return;
        }
        vt_btn->setEnabled(false);
        const QString sha = sha256;
        std::thread([this, sha, vt_btn] {
            const std::string result = engine_->LookupVirusTotal(sha.toStdString());
            if (AppQuitting().load()) return;
            QMetaObject::invokeMethod(this, [this, result, vt_btn] {
                vt_btn->setEnabled(true);
                QMessageBox::information(this, "VirusTotal",
                    QString::fromUtf8(result.c_str()));
            }, Qt::QueuedConnection);
        }).detach();
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // SCAN BUTTON CONNECTIONS (keep all existing functionality)
    // ═══════════════════════════════════════════════════════════════════════════
    connect(scan_folder_button_,      &QPushButton::clicked, this, &MainWindow::OnScanFolderClicked);
    connect(scan_files_button_,       &QPushButton::clicked, this, &MainWindow::OnScanFilesClicked);
    connect(scan_registry_button_,    &QPushButton::clicked, this, &MainWindow::OnScanRegistryClicked);
    connect(scan_memory_button_,      &QPushButton::clicked, this, &MainWindow::OnScanMemoryClicked);
    connect(scan_persistence_button_, &QPushButton::clicked, this, &MainWindow::OnScanPersistenceClicked);
    connect(cancel_scan_button_,      &QPushButton::clicked, this, &MainWindow::OnCancelScanClicked);
    connect(clear_btn,                &QPushButton::clicked, this, &MainWindow::OnClearHistoryClicked);
    connect(export_btn,               &QPushButton::clicked, this, &MainWindow::OnExportDetectionsClicked);

    // Also wire prog_bar visibility to scan_progress_ visibility changes
    scan_progress_->setVisible(false);
    scan_files_label_->setVisible(false);
    prog_bar_widget->setVisible(false);

    // Initial card load
    if (*refresh_fn) (*refresh_fn)();

    return page;
}

} // namespace avdashboard
