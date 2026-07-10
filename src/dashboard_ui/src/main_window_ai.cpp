#include "main_window.hpp"

#include <cmath>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include <QEasingCurve>
#include <QFileDialog>
#include <QFont>
#include <QFrame>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSizePolicy>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include "avai/llm_assistant.hpp"
#include "avcore/severity.hpp"
#include "avengine/engine.hpp"
#include "av_quit_guard.hpp"

namespace avdashboard {

namespace {

// ─── AiAvatarWidget ──────────────────────────────────────────────────────────
class AiAvatarWidget : public QWidget {
public:
    enum class State { Idle, Thinking, Responding };
    explicit AiAvatarWidget(int sz, QWidget* parent = nullptr)
        : QWidget(parent), sz_(sz) {
        setFixedSize(sz, sz);
        setAttribute(Qt::WA_TransparentForMouseEvents);
        timer_ = new QTimer(this);
        timer_->setInterval(40);
        connect(timer_, &QTimer::timeout, this, [this] {
            phase_ += 0.08f;
            if (phase_ > 6.28318f) phase_ -= 6.28318f;
            update();
        });
    }
    void setState(State s) {
        state_ = s;
        if (s == State::Idle) timer_->stop();
        else timer_->start();
        update();
    }
    State state() const { return state_; }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const float cx = sz_ / 2.0f, cy = sz_ / 2.0f, r = sz_ / 2.0f - 2.0f;
        const QPointF center(cx, cy);
        if (state_ != State::Idle) {
            for (int i = 0; i < 3; ++i) {
                float rp = phase_ - i * 2.094f;
                float t  = std::fmod(rp / 6.28318f + 2.0f, 1.0f);
                float rr = r + 3.0f + t * r * 1.05f;
                int   a  = static_cast<int>((1.0f - t) *
                           (state_ == State::Thinking ? 155.0f : 100.0f));
                if (a < 1) a = 1;
                p.setPen(QPen(QColor(255, 122, 0, a), 1.5f));
                p.setBrush(Qt::NoBrush);
                p.drawEllipse(center, static_cast<double>(rr), static_cast<double>(rr));
            }
        }
        QRadialGradient grad(center, r);
        if (state_ == State::Idle) {
            grad.setColorAt(0.0, QColor(40, 20, 0));
            grad.setColorAt(0.6, QColor(25, 10, 0));
            grad.setColorAt(1.0, QColor(10, 4, 0));
        } else if (state_ == State::Thinking) {
            float pulse = 0.5f + 0.5f * std::sin(phase_ * 2.5f);
            int c0 = 100 + static_cast<int>(pulse * 80.0f);
            grad.setColorAt(0.0, QColor(255, c0, 0));
            grad.setColorAt(0.6, QColor(180, 60, 0));
            grad.setColorAt(1.0, QColor(30, 10, 0));
        } else {
            float pulse = 0.5f + 0.5f * std::sin(phase_ * 4.0f);
            int c0 = 150 + static_cast<int>(pulse * 75.0f);
            grad.setColorAt(0.0, QColor(255, c0, 0));
            grad.setColorAt(0.5, QColor(255, 90, 0));
            grad.setColorAt(1.0, QColor(60, 15, 0));
        }
        p.setBrush(grad);
        int borderA = (state_ == State::Idle) ? 80 : 200;
        p.setPen(QPen(QColor(255, 122, 0, borderA), 2.0f));
        p.drawEllipse(center, static_cast<double>(r), static_cast<double>(r));
        if (state_ == State::Responding) {
            p.setBrush(Qt::NoBrush);
            float ar = r - 1.5f;
            QRectF arc(cx - ar, cy - ar, ar * 2.0f, ar * 2.0f);
            int startDeg16 = static_cast<int>(-phase_ * (180.0f / 3.14159f) * 16.0f);
            p.setPen(QPen(QColor(255, 180, 60, 210), 2.5f, Qt::SolidLine, Qt::RoundCap));
            p.drawArc(arc, startDeg16, 120 * 16);
        }
        p.setPen(Qt::white);
        int fs = (sz_ >= 40) ? sz_ / 4 : sz_ / 5;
        p.setFont(QFont("Segoe UI", fs, QFont::Bold));
        p.drawText(QRectF(0.0, 0.0, sz_, sz_), Qt::AlignCenter, "AI");
    }
private:
    int sz_; QTimer* timer_ = nullptr; float phase_ = 0.0f; State state_ = State::Idle;
};

// ─── AiThinkingDots ──────────────────────────────────────────────────────────
class AiThinkingDots : public QWidget {
public:
    explicit AiThinkingDots(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedSize(52, 22);
        timer_ = new QTimer(this);
        timer_->setInterval(50);
        connect(timer_, &QTimer::timeout, this, [this] {
            phase_ = (phase_ + 1) % 36;
            update();
        });
        timer_->start();
    }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const float cx[] = {10.0f, 26.0f, 42.0f};
        for (int i = 0; i < 3; ++i) {
            const float t = std::fmod(static_cast<float>(phase_) / 36.0f + i * 0.333f, 1.0f);
            const float bounce = static_cast<float>(std::sin(t * 3.14159265f));
            const float y_off = bounce * 4.5f;
            const float alpha = 0.35f + bounce * 0.65f;
            const float r = 3.5f + bounce * 0.8f;
            p.setBrush(QColor(0xFF, 0x7A, 0x00, static_cast<int>(alpha * 255)));
            p.setPen(Qt::NoPen);
            p.drawEllipse(QPointF(cx[i], 11.0f - y_off), r, r);
        }
    }
private:
    QTimer* timer_; int phase_ = 0;
};

// ─── AiPageIcon ──────────────────────────────────────────────────────────────
class AiPageIcon : public QWidget {
public:
    enum Type {
        Shield, ShieldCheck, Bot, User, MessageSquare, AlertTriangle,
        Plus, Settings, Bell, FileSearch, FileText, Code, TrendingUp,
        Activity, Zap, RefreshCw, Eye, Hash, Sparkles, Paperclip,
        Scan, Mic, MoreHorizontal, Lock, Terminal, ChevronRight, Bug
    };
    AiPageIcon(Type t, int sz, QColor c, QWidget* parent = nullptr)
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
            QPainterPath path;
            path.moveTo(12,2); path.lineTo(21,6); path.lineTo(21,12);
            path.cubicTo(21,17,16.5,21,12,22);
            path.cubicTo(7.5,21,3,17,3,12);
            path.lineTo(3,6); path.closeSubpath();
            p.drawPath(path); break;
        }
        case ShieldCheck: {
            QPainterPath sh;
            sh.moveTo(12,2); sh.lineTo(21,6); sh.lineTo(21,12);
            sh.cubicTo(21,17,16.5,21,12,22);
            sh.cubicTo(7.5,21,3,17,3,12);
            sh.lineTo(3,6); sh.closeSubpath();
            p.drawPath(sh);
            p.drawLine(QPointF(8.5,12),QPointF(11,14.5));
            p.drawLine(QPointF(11,14.5),QPointF(15.5,9));
            break;
        }
        case Bot: {
            p.drawRoundedRect(QRectF(4,6,16,13),2.5,2.5);
            p.drawLine(QPointF(12,6),QPointF(12,3));
            p.setBrush(color_);
            p.drawEllipse(QPointF(12,2.5),1.2,1.2);
            p.drawEllipse(QPointF(9,12),1.5,1.5);
            p.drawEllipse(QPointF(15,12),1.5,1.5);
            p.setBrush(Qt::NoBrush);
            p.drawLine(QPointF(9,16),QPointF(15,16));
            p.drawLine(QPointF(4,12),QPointF(2,12));
            p.drawLine(QPointF(20,12),QPointF(22,12));
            break;
        }
        case User: {
            p.drawEllipse(QPointF(12,7.5),4,4);
            QPainterPath body;
            body.moveTo(4,20);
            body.cubicTo(4,16,8,14,12,14);
            body.cubicTo(16,14,20,16,20,20);
            p.drawPath(body); break;
        }
        case MessageSquare: {
            p.drawRoundedRect(QRectF(3,3,18,14),2.5,2.5);
            p.drawLine(QPointF(3,17),QPointF(7,21));
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
        case Plus:
            p.drawLine(QPointF(12,4),QPointF(12,20));
            p.drawLine(QPointF(4,12),QPointF(20,12));
            break;
        case Settings: {
            p.drawEllipse(QPointF(12,12),3.5,3.5);
            for (int i=0;i<8;++i) {
                const double a = i*3.14159265/4.0;
                p.drawLine(QPointF(12+6*std::cos(a),12+6*std::sin(a)),
                           QPointF(12+8*std::cos(a),12+8*std::sin(a)));
            }
            break;
        }
        case Bell: {
            QPainterPath bell;
            bell.moveTo(12,3);
            bell.cubicTo(8,3,5,6,5,10);
            bell.lineTo(5,16); bell.lineTo(19,16); bell.lineTo(19,10);
            bell.cubicTo(19,6,16,3,12,3); bell.closeSubpath();
            p.drawPath(bell);
            p.drawLine(QPointF(10,16),QPointF(10,19));
            p.drawLine(QPointF(14,16),QPointF(14,19));
            p.drawLine(QPointF(10,19),QPointF(14,19));
            break;
        }
        case FileSearch: {
            QPainterPath file;
            file.moveTo(13,2); file.lineTo(3,2); file.lineTo(3,22);
            file.lineTo(21,22); file.lineTo(21,10); file.closeSubpath();
            p.drawPath(file);
            p.drawLine(QPointF(13,2),QPointF(13,10));
            p.drawLine(QPointF(13,10),QPointF(21,10));
            p.drawEllipse(QPointF(11,15),2.5,2.5);
            p.drawLine(QPointF(13,17),QPointF(15.5,19));
            break;
        }
        case FileText: {
            QPainterPath file;
            file.moveTo(13,2); file.lineTo(3,2); file.lineTo(3,22);
            file.lineTo(21,22); file.lineTo(21,10); file.closeSubpath();
            p.drawPath(file);
            p.drawLine(QPointF(13,2),QPointF(13,10));
            p.drawLine(QPointF(13,10),QPointF(21,10));
            p.drawLine(QPointF(8,13),QPointF(16,13));
            p.drawLine(QPointF(8,16),QPointF(16,16));
            p.drawLine(QPointF(8,19),QPointF(12,19));
            break;
        }
        case Code:
            p.drawLine(QPointF(16,18),QPointF(20,12));
            p.drawLine(QPointF(20,12),QPointF(16,6));
            p.drawLine(QPointF(8,6),QPointF(4,12));
            p.drawLine(QPointF(4,12),QPointF(8,18));
            p.drawLine(QPointF(14.5,4),QPointF(9.5,20));
            break;
        case TrendingUp:
            p.drawLine(QPointF(3,17),QPointF(9,11));
            p.drawLine(QPointF(9,11),QPointF(13,15));
            p.drawLine(QPointF(13,15),QPointF(21,7));
            p.drawLine(QPointF(17,7),QPointF(21,7));
            p.drawLine(QPointF(21,7),QPointF(21,11));
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
        case RefreshCw: {
            QPainterPath arc;
            arc.arcMoveTo(3,3,18,18,60);
            arc.arcTo(3,3,18,18,60,-300);
            p.drawPath(arc);
            p.drawLine(QPointF(20,4),QPointF(20,8));
            p.drawLine(QPointF(20,8),QPointF(16,8));
            break;
        }
        case Eye: {
            QPainterPath outline;
            outline.moveTo(1,12);
            outline.cubicTo(5,6,9,4,12,4);
            outline.cubicTo(15,4,19,6,23,12);
            outline.cubicTo(19,18,15,20,12,20);
            outline.cubicTo(9,20,5,18,1,12);
            p.drawPath(outline);
            p.drawEllipse(QPointF(12,12),3,3);
            break;
        }
        case Hash:
            p.drawLine(QPointF(4,9),QPointF(20,9));
            p.drawLine(QPointF(4,15),QPointF(20,15));
            p.drawLine(QPointF(10,3),QPointF(8,21));
            p.drawLine(QPointF(16,3),QPointF(14,21));
            break;
        case Sparkles:
            p.setBrush(color_);
            p.drawEllipse(QPointF(12,2),1.5,1.5);
            p.drawEllipse(QPointF(19,4),1,1);
            p.drawEllipse(QPointF(5,20),1,1);
            p.setBrush(Qt::NoBrush);
            p.drawLine(QPointF(12,6),QPointF(14,9));
            p.drawLine(QPointF(14,9),QPointF(12,12));
            p.drawLine(QPointF(12,12),QPointF(10,9));
            p.drawLine(QPointF(10,9),QPointF(12,6));
            p.drawLine(QPointF(5,6),QPointF(6,8));
            p.drawLine(QPointF(6,8),QPointF(5,10));
            p.drawLine(QPointF(5,10),QPointF(4,8));
            p.drawLine(QPointF(4,8),QPointF(5,6));
            break;
        case Paperclip: {
            QPainterPath pp;
            pp.arcMoveTo(8,5,8,11,90);
            pp.arcTo(8,5,8,11,90,270);
            pp.arcTo(5,9,14,14,180,-180);
            p.drawPath(pp); break;
        }
        case Scan:
            p.drawLine(QPointF(3,7),QPointF(3,3)); p.drawLine(QPointF(3,3),QPointF(7,3));
            p.drawLine(QPointF(17,3),QPointF(21,3)); p.drawLine(QPointF(21,3),QPointF(21,7));
            p.drawLine(QPointF(21,17),QPointF(21,21)); p.drawLine(QPointF(21,21),QPointF(17,21));
            p.drawLine(QPointF(7,21),QPointF(3,21)); p.drawLine(QPointF(3,21),QPointF(3,17));
            p.drawLine(QPointF(3,12),QPointF(21,12));
            break;
        case Mic:
            p.drawRoundedRect(QRectF(9,2,6,13),3,3);
            { QPainterPath arc; arc.arcMoveTo(5,9,14,12,0); arc.arcTo(5,9,14,12,0,-180); p.drawPath(arc); }
            p.drawLine(QPointF(12,21),QPointF(12,17));
            p.drawLine(QPointF(9,21),QPointF(15,21));
            break;
        case MoreHorizontal:
            p.setBrush(color_);
            p.drawEllipse(QPointF(5,12),1.2,1.2);
            p.drawEllipse(QPointF(12,12),1.2,1.2);
            p.drawEllipse(QPointF(19,12),1.2,1.2);
            p.setBrush(Qt::NoBrush);
            break;
        case Lock:
            p.drawRoundedRect(QRectF(3,11,18,11),2,2);
            { QPainterPath arc; arc.arcMoveTo(8,3,8,10,0); arc.arcTo(8,3,8,10,0,180); p.drawPath(arc); }
            p.setBrush(color_);
            p.drawEllipse(QPointF(12,16),1.5,1.5);
            p.setBrush(Qt::NoBrush);
            break;
        case Terminal:
            p.drawRoundedRect(QRectF(2,3,20,18),2,2);
            p.drawLine(QPointF(6,9),QPointF(10,12));
            p.drawLine(QPointF(10,12),QPointF(6,15));
            p.drawLine(QPointF(13,15),QPointF(18,15));
            break;
        case ChevronRight:
            p.drawLine(QPointF(9,5),QPointF(16,12));
            p.drawLine(QPointF(16,12),QPointF(9,19));
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
        default: break;
        }
    }
private:
    Type type_; QColor color_;
};

// ─── MarkdownToHtml ───────────────────────────────────────────────────────────
static QString MarkdownToHtml(const QString& src) {
    const QString h = src.toHtmlEscaped();
    QString out; out.reserve(h.size() * 2);
    const int n = h.size(); int i = 0;
    while (i < n) {
        const QChar c = h[i];
        if (c == QLatin1Char('*') && i+1<n && h[i+1]==QLatin1Char('*')) {
            const int end = h.indexOf(QLatin1String("**"), i+2);
            if (end != -1) {
                out += QLatin1String("<b>") + h.mid(i+2,end-i-2) + QLatin1String("</b>");
                i = end+2; continue;
            }
        }
        if (c == QLatin1Char('`')) {
            const int end = h.indexOf(QLatin1Char('`'), i+1);
            if (end != -1) {
                out += QLatin1String("<code style='background:rgba(255,122,0,0.12);"
                       "padding:1px 5px;border-radius:3px;"
                       "font-family:Consolas,monospace;font-size:9pt;color:#FF9B3D;'>")
                     + h.mid(i+1,end-i-1) + QLatin1String("</code>");
                i = end+1; continue;
            }
        }
        if (c == QLatin1Char('\n')) { out += QLatin1String("<br>"); ++i; continue; }
        out += c; ++i;
    }
    return out;
}

// ─── MakeBubble ───────────────────────────────────────────────────────────────
// Returns (row widget, inner text label)
static QLabel* MakeBubble(const QString& text, Qt::Alignment align, QWidget* parent,
                           bool is_dots = false) {
    auto* row = new QWidget(parent);
    row->setStyleSheet("background: transparent;");
    auto* row_layout = new QHBoxLayout(row);
    row_layout->setContentsMargins(16, 3, 16, 3);
    row_layout->setSpacing(10);

    if (align == Qt::AlignRight) {
        // User bubble — right-aligned amber
        auto* bubble = new QFrame(row);
        bubble->setFrameShape(QFrame::NoFrame);
        bubble->setMaximumWidth(580);
        bubble->setStyleSheet(
            "QFrame {"
            " background: rgba(36,23,14,242);"
            " border: 1px solid rgba(255,170,90,36);"
            " border-radius: 18px 18px 4px 18px;"
            "}");
        auto* blayout = new QVBoxLayout(bubble);
        blayout->setContentsMargins(14, 10, 14, 10);
        auto* lbl = new QLabel(text, bubble);
        lbl->setObjectName("msg_text");
        lbl->setWordWrap(true);
        lbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
        lbl->setStyleSheet("color: #ffffff; font-size: 10pt; background: transparent;");
        lbl->setFont(QFont("Segoe UI", 10));
        blayout->addWidget(lbl);

        // User icon box
        auto* icon_box = new QFrame(row);
        icon_box->setFixedSize(36,36);
        icon_box->setStyleSheet(
            "QFrame {"
            " background: rgba(255,255,255,18);"
            " border: 1px solid rgba(255,255,255,23);"
            " border-radius: 10px;"
            "}");
        auto* icon_box_l = new QVBoxLayout(icon_box);
        icon_box_l->setContentsMargins(9,9,9,9);
        icon_box_l->addWidget(new AiPageIcon(AiPageIcon::User, 16, QColor(0xC7,0xB6,0xA2), icon_box));

        row_layout->addStretch();
        row_layout->addWidget(bubble);
        row_layout->addWidget(icon_box, 0, Qt::AlignTop);
        return lbl;
    } else {
        // AI bubble — left-aligned dark
        // Bot icon box
        auto* bot_box = new QFrame(row);
        bot_box->setFixedSize(36,36);
        bot_box->setStyleSheet(
            "QFrame {"
            " background: rgba(255,122,0,33);"
            " border: 1px solid rgba(255,122,0,56);"
            " border-radius: 10px;"
            "}");
        auto* bot_box_l = new QVBoxLayout(bot_box);
        bot_box_l->setContentsMargins(9,9,9,9);
        bot_box_l->addWidget(new AiPageIcon(AiPageIcon::Bot, 16, QColor(0xFF,0x7A,0x00), bot_box));

        auto* bubble = new QFrame(row);
        bubble->setFrameShape(QFrame::NoFrame);
        bubble->setMaximumWidth(580);
        bubble->setStyleSheet(
            "QFrame {"
            " background: rgba(26,18,12,216);"
            " border: 1px solid rgba(255,170,90,23);"
            " border-radius: 4px 18px 18px 18px;"
            "}");
        auto* blayout = new QVBoxLayout(bubble);
        blayout->setContentsMargins(14, 10, 14, 10);

        QLabel* lbl = nullptr;
        if (is_dots) {
            auto* dots = new AiThinkingDots(bubble);
            blayout->addWidget(dots);
            lbl = nullptr; // dots widget, no text label
        } else {
            lbl = new QLabel(text, bubble);
            lbl->setObjectName("msg_text");
            lbl->setWordWrap(true);
            lbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
            lbl->setStyleSheet("color: #E8D8C8; font-size: 10pt; background: transparent;");
            lbl->setFont(QFont("Segoe UI", 10));
            blayout->addWidget(lbl);
        }

        row_layout->addWidget(bot_box, 0, Qt::AlignTop);
        row_layout->addWidget(bubble, 1);
        row_layout->addStretch();
        return lbl;
    }
}

// ─── MakeIconBtn ─────────────────────────────────────────────────────────────
static QPushButton* MakeIconBtn(AiPageIcon::Type t, QWidget* parent) {
    auto* btn = new QPushButton(parent);
    btn->setFixedSize(30,30);
    btn->setStyleSheet(
        "QPushButton { background: transparent; border: none; border-radius: 6px; }"
        "QPushButton:hover { background: rgba(255,170,90,20); }");
    auto* icon = new AiPageIcon(t, 16, QColor(0x4A,0x3B,0x30), btn);
    auto* l = new QVBoxLayout(btn);
    l->setContentsMargins(7,7,7,7);
    l->addWidget(icon);
    return btn;
}

} // namespace

void MainWindow::OpenAiWithPrompt(const QString& prompt) {
    GoToPage(6); // AI Assistant page
    if (ai_assistant_ && ai_input_edit_ && ai_input_edit_->isEnabled()) {
        ai_input_edit_->setText(prompt);
        ai_input_edit_->setFocus();
    } else {
        QMessageBox::information(this, QString::fromUtf8("AI model not loaded"),
            QString::fromUtf8("Load the AI model first (Load button), then try again.\n\nPrompt:\n") + prompt);
    }
}

// ─── BuildAiPage ─────────────────────────────────────────────────────────────
QWidget* MainWindow::BuildAiPage() {
    auto* page = new QWidget();
    page->setStyleSheet("QWidget { background: #120B06; }");
    ArmQuitGuard(page);

    auto* root = new QHBoxLayout(page);
    root->setContentsMargins(0,0,0,0);
    root->setSpacing(0);

    // ═══════════════════════════════════════════════════════════════════════════
    // LEFT SIDEBAR (240px)
    // ═══════════════════════════════════════════════════════════════════════════
    auto* sidebar = new QWidget(page);
    sidebar->setFixedWidth(240);
    sidebar->setStyleSheet(
        "QWidget { background: rgba(14,9,4,255);"
        " border-right: 1px solid rgba(255,170,90,18); }");

    auto* sb_layout = new QVBoxLayout(sidebar);
    sb_layout->setContentsMargins(0,0,0,0);
    sb_layout->setSpacing(0);

    // Logo row
    auto* logo_area = new QWidget(sidebar);
    logo_area->setStyleSheet(
        "QWidget { border-bottom: 1px solid rgba(255,170,90,15); }");
    auto* logo_l = new QHBoxLayout(logo_area);
    logo_l->setContentsMargins(16,16,16,14);
    logo_l->setSpacing(10);

    auto* logo_box = new QFrame(logo_area);
    logo_box->setFixedSize(34,34);
    logo_box->setStyleSheet(
        "QFrame { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
        " stop:0 #FF7A00, stop:1 #E55A00);"
        " border-radius: 10px; border: none; }");
    auto* logo_box_l = new QVBoxLayout(logo_box);
    logo_box_l->setContentsMargins(8,8,8,8);
    logo_box_l->addWidget(new AiPageIcon(AiPageIcon::Shield, 18, Qt::white, logo_box));
    logo_l->addWidget(logo_box);

    auto* logo_texts = new QVBoxLayout();
    logo_texts->setSpacing(1);
    auto* logo_name = new QLabel("TeoAVSuite", logo_area);
    logo_name->setStyleSheet("color:#ffffff; font-size:13pt; font-weight:700; background:transparent;");
    auto* logo_sub = new QLabel("AI Security", logo_area);
    logo_sub->setStyleSheet("color:#FF9B3D; font-size:10pt; background:transparent;");
    logo_texts->addWidget(logo_name);
    logo_texts->addWidget(logo_sub);
    logo_l->addLayout(logo_texts);
    logo_l->addStretch();
    logo_l->addWidget(new AiPageIcon(AiPageIcon::Lock, 14, QColor(0x4A,0x3B,0x30), logo_area));
    sb_layout->addWidget(logo_area);

    // New Conversation button
    auto* new_conv_area = new QWidget(sidebar);
    new_conv_area->setStyleSheet("QWidget { background: transparent; }");
    auto* new_conv_l = new QVBoxLayout(new_conv_area);
    new_conv_l->setContentsMargins(12,10,12,6);
    auto* new_conv_btn = new QPushButton(new_conv_area);
    new_conv_btn->setFixedHeight(38);
    new_conv_btn->setStyleSheet(
        "QPushButton { background: rgba(255,122,0,25);"
        " border: 1px solid rgba(255,122,0,46);"
        " border-radius: 10px; color:#ffffff;"
        " font-size:11.5pt; font-weight:500;"
        " text-align:left; padding-left:10px; }"
        "QPushButton:hover { background: rgba(255,122,0,46); }");
    {
        auto* btn_l = new QHBoxLayout(new_conv_btn);
        btn_l->setContentsMargins(10,0,10,0);
        btn_l->setSpacing(8);
        auto* plus_icon = new AiPageIcon(AiPageIcon::Plus, 15, QColor(0xFF,0x7A,0x00), new_conv_btn);
        plus_icon->setAttribute(Qt::WA_TransparentForMouseEvents, false);
        auto* btn_lbl = new QLabel(QString::fromUtf8("New Conversation"), new_conv_btn);
        btn_lbl->setStyleSheet("color:#ffffff; font-size:11pt; font-weight:500; background:transparent;");
        btn_l->addWidget(plus_icon);
        btn_l->addWidget(btn_lbl);
        btn_l->addStretch();
    }
    new_conv_l->addWidget(new_conv_btn);
    sb_layout->addWidget(new_conv_area);

    // Conversations + Tools scrollable area
    auto* sb_scroll = new QScrollArea(sidebar);
    sb_scroll->setWidgetResizable(true);
    sb_scroll->setFrameShape(QFrame::NoFrame);
    sb_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    sb_scroll->setStyleSheet(
        "QScrollArea { background: transparent; border: none; }"
        "QScrollBar:vertical { background:transparent; width:3px; margin:0; }"
        "QScrollBar::handle:vertical { background:rgba(255,170,90,40); border-radius:1px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }");
    auto* sb_inner = new QWidget(sb_scroll);
    sb_inner->setStyleSheet("background: transparent;");
    auto* sb_inner_l = new QVBoxLayout(sb_inner);
    sb_inner_l->setContentsMargins(12,8,12,8);
    sb_inner_l->setSpacing(2);

    // "RECENT" heading
    auto* recent_lbl = new QLabel("RECENT", sb_inner);
    recent_lbl->setStyleSheet(
        "color:#33261A; font-size:9pt; font-weight:700; letter-spacing:1px;"
        " background:transparent; padding:4px 4px 4px 4px;");
    sb_inner_l->addWidget(recent_lbl);

    // Reusable actions so sidebar / quick-action buttons DO something even
    // before the AI model is loaded (previously they silently prefilled text
    // only when the input was enabled, so they looked decorative).
    auto aiPrefill = [this](const QString& text) {
        if (ai_assistant_ && ai_input_edit_ && ai_input_edit_->isEnabled()) {
            ai_input_edit_->setText(text);
            ai_input_edit_->setFocus();
        } else {
            QMessageBox::information(this, QString::fromUtf8("AI model not loaded"),
                QString::fromUtf8("Load the AI model first (Load button), then try again."));
        }
    };
    auto doAnalyzeFile = [this] {
        const QString f = QFileDialog::getOpenFileName(
            this, QString::fromUtf8("Choose a file to scan"), QString(),
            QString::fromUtf8("All files (*.*)"));
        if (f.isEmpty()) return;
        const std::string path = f.toStdString();
        std::thread([this, path] { engine_->ScanFile(path); }).detach();
        GoToPage(1); // detection results appear on the History page
    };
    auto doThreatReport = [this] {
        const auto recent = engine_->RecentDetections(50);
        QString rpt;
        if (recent.empty()) {
            rpt = QString::fromUtf8("No detections to report yet.");
        } else {
            rpt = QString::fromUtf8("Recent detections: %1\n\n")
                      .arg(static_cast<int>(recent.size()));
            for (const auto& ev : recent) {
                const char* sev = ev.severity == avcore::Severity::Malicious ? "MALICIOUS"
                                : ev.severity == avcore::Severity::Suspicious ? "SUSPICIOUS" : "INFO";
                rpt += QString::fromStdString(std::string("[") + sev + "] " + ev.rule_id
                                              + "\n    " + ev.target_path + "\n");
            }
        }
        QMessageBox box(this);
        box.setWindowTitle(QString::fromUtf8("Threat Report"));
        box.setIcon(QMessageBox::Information);
        box.setText(QString::fromUtf8("Recent detections summary"));
        box.setDetailedText(rpt);
        box.exec();
    };

    // Recent conversation items — clickable: each seeds a topic prompt.
    auto makeConvItem = [&](const QString& title, const QString& preview,
                             const QString& age, bool has_alert,
                             std::function<void()> onClick) -> QWidget* {
        auto* item = new QPushButton(sb_inner);
        item->setCursor(Qt::PointingHandCursor);
        // QPushButton clips its content to sizeHint; a 2-line (title+preview)
        // layout gets its bottom row cut off ("half the text hidden") unless we
        // reserve enough height explicitly.
        item->setMinimumHeight(54);
        item->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
        item->setStyleSheet(
            "QPushButton { text-align:left; background:transparent;"
            " border-radius:9px; border:1px solid transparent; }"
            "QPushButton:hover { background:rgba(255,122,0,15);"
            " border-color:rgba(255,122,0,30); }");
        QObject::connect(item, &QPushButton::clicked, item,
                         [onClick] { if (onClick) onClick(); });
        auto* il = new QHBoxLayout(item);
        il->setContentsMargins(8,7,8,7);
        il->setSpacing(8);
        auto* ico = new AiPageIcon(has_alert ? AiPageIcon::AlertTriangle : AiPageIcon::MessageSquare,
                                   13,
                                   has_alert ? QColor(0xFF,0x5A,0x6A) : QColor(0x4A,0x3B,0x30),
                                   item);
        il->addWidget(ico, 0, Qt::AlignVCenter);
        auto* text_col = new QVBoxLayout();
        text_col->setSpacing(2);
        auto* t = new QLabel(title, item);
        t->setStyleSheet("color:#C7B6A2; font-size:11pt; font-weight:500; background:transparent;");
        auto* pr = new QLabel(preview, item);
        pr->setStyleSheet("color:#4A3B30; font-size:9.5pt; background:transparent;");
        text_col->addWidget(t);
        text_col->addWidget(pr);
        il->addLayout(text_col, 1);
        auto* age_lbl = new QLabel(age, item);
        age_lbl->setFixedWidth(24);
        age_lbl->setStyleSheet("color:#33261A; font-size:9pt; background:transparent;");
        age_lbl->setAlignment(Qt::AlignVCenter | Qt::AlignRight);
        il->addWidget(age_lbl, 0, Qt::AlignVCenter);
        return item;
    };

    sb_inner_l->addWidget(makeConvItem(
        "Malware Analysis", "emotet dropper...", "2m", true,
        [aiPrefill] { aiPrefill(QString::fromUtf8("Analyze this malware sample: ")); }));
    sb_inner_l->addWidget(makeConvItem(
        "YARA Rule Gen", "Generate rule for...", "1h", false,
        [aiPrefill] { aiPrefill(QString::fromUtf8("Help me generate a YARA rule for: ")); }));
    sb_inner_l->addWidget(makeConvItem(
        "Log Investigation", "ETW events from...", "3h", false,
        [aiPrefill] { aiPrefill(QString::fromUtf8("Investigate these ETW / security logs: ")); }));

    // Separator
    auto* sb_sep = new QFrame(sb_inner);
    sb_sep->setFrameShape(QFrame::HLine);
    sb_sep->setStyleSheet("background:rgba(255,170,90,18); border:none; max-height:1px;");
    sb_sep->setFixedHeight(1);
    sb_inner_l->addWidget(sb_sep);
    sb_inner_l->addSpacing(6);

    // "TOOLS" heading
    auto* tools_lbl = new QLabel("TOOLS", sb_inner);
    tools_lbl->setStyleSheet(
        "color:#33261A; font-size:9pt; font-weight:700; letter-spacing:1px;"
        " background:transparent; padding:4px 4px 4px 4px;");
    sb_inner_l->addWidget(tools_lbl);

    // Tool buttons
    auto makeToolBtn = [&](AiPageIcon::Type ico, const QString& label) -> QPushButton* {
        auto* btn = new QPushButton(sb_inner);
        btn->setFixedHeight(34);
        btn->setStyleSheet(
            "QPushButton { background:transparent; border:none; border-radius:8px;"
            " text-align:left; padding-left:6px; }"
            "QPushButton:hover { background:rgba(255,255,255,8); }");
        auto* bl = new QHBoxLayout(btn);
        bl->setContentsMargins(8,0,8,0);
        bl->setSpacing(8);
        bl->addWidget(new AiPageIcon(ico, 13, QColor(0x4A,0x3B,0x30), btn));
        auto* tl = new QLabel(label, btn);
        tl->setStyleSheet("color:#6B5B4E; font-size:11pt; background:transparent;");
        bl->addWidget(tl);
        bl->addStretch();
        return btn;
    };

    auto* tool_analyze  = makeToolBtn(AiPageIcon::FileSearch, "Analyze File");
    auto* tool_logs     = makeToolBtn(AiPageIcon::Activity,   "Analyze Logs");
    auto* tool_yara     = makeToolBtn(AiPageIcon::Code,       "YARA Assistant");
    auto* tool_reports  = makeToolBtn(AiPageIcon::TrendingUp, "Threat Reports");
    sb_inner_l->addWidget(tool_analyze);
    sb_inner_l->addWidget(tool_logs);
    sb_inner_l->addWidget(tool_yara);
    sb_inner_l->addWidget(tool_reports);
    sb_inner_l->addStretch();
    sb_scroll->setWidget(sb_inner);
    sb_layout->addWidget(sb_scroll, 1);

    // Bottom: Settings + online dot
    auto* sb_bottom = new QWidget(sidebar);
    sb_bottom->setStyleSheet(
        "QWidget { border-top: 1px solid rgba(255,170,90,15); }");
    auto* sb_bot_l = new QHBoxLayout(sb_bottom);
    sb_bot_l->setContentsMargins(16,10,16,10);
    sb_bot_l->setSpacing(8);
    sb_bot_l->addWidget(new AiPageIcon(AiPageIcon::Settings, 15, QColor(0x4A,0x3B,0x30), sb_bottom));
    auto* sb_settings_lbl = new QLabel("Settings", sb_bottom);
    sb_settings_lbl->setStyleSheet("color:#6B5B4E; font-size:11pt; background:transparent;");
    sb_bot_l->addWidget(sb_settings_lbl);
    sb_bot_l->addStretch();
    // Green online dot
    auto* online_dot = new QLabel(sb_bottom);
    online_dot->setFixedSize(8,8);
    online_dot->setStyleSheet(
        "QLabel { background:#4ADE80; border-radius:4px;"
        " border: none; }");
    sb_bot_l->addWidget(online_dot);
    sb_layout->addWidget(sb_bottom);
    root->addWidget(sidebar);

    // ═══════════════════════════════════════════════════════════════════════════
    // CENTER (expanding)
    // ═══════════════════════════════════════════════════════════════════════════
    auto* center = new QWidget(page);
    center->setStyleSheet("QWidget { background: #120B06; }");
    auto* center_l = new QVBoxLayout(center);
    center_l->setContentsMargins(0,0,0,0);
    center_l->setSpacing(0);

    // Center header bar
    auto* ctr_hdr = new QWidget(center);
    ctr_hdr->setFixedHeight(62);
    ctr_hdr->setStyleSheet(
        "QWidget { background: rgba(14,9,4,234);"
        " border-bottom: 1px solid rgba(255,170,90,18); }");
    auto* ctr_hdr_l = new QHBoxLayout(ctr_hdr);
    ctr_hdr_l->setContentsMargins(20,0,16,0);
    ctr_hdr_l->setSpacing(12);

    // Bot icon box 38x38
    auto* hdr_bot_box = new QFrame(ctr_hdr);
    hdr_bot_box->setFixedSize(38,38);
    hdr_bot_box->setStyleSheet(
        "QFrame { background:rgba(255,122,0,28);"
        " border:1px solid rgba(255,122,0,51);"
        " border-radius:11px; }");
    auto* hdr_bot_box_l = new QVBoxLayout(hdr_bot_box);
    hdr_bot_box_l->setContentsMargins(9,9,9,9);
    hdr_bot_box_l->addWidget(new AiPageIcon(AiPageIcon::Bot, 18, QColor(0xFF,0x7A,0x00), hdr_bot_box));
    ctr_hdr_l->addWidget(hdr_bot_box);

    auto* hdr_text_col = new QVBoxLayout();
    hdr_text_col->setSpacing(2);
    auto* hdr_title = new QLabel("TeoAV Assistant", ctr_hdr);
    hdr_title->setStyleSheet(
        "color:#ffffff; font-size:13pt; font-weight:700; background:transparent;");
    auto* hdr_sub_row = new QHBoxLayout();
    hdr_sub_row->setSpacing(5);
    auto* hdr_green_dot = new QLabel(ctr_hdr);
    hdr_green_dot->setFixedSize(6,6);
    hdr_green_dot->setStyleSheet(
        "QLabel { background:#4ADE80; border-radius:3px; border:none; }");
    auto* hdr_sub = new QLabel("AI Security Analyst " "\xc2\xb7" " Online", ctr_hdr);
    hdr_sub->setStyleSheet("color:#6B5B4E; font-size:9.5pt; background:transparent;");
    hdr_sub_row->addWidget(hdr_green_dot);
    hdr_sub_row->addWidget(hdr_sub);
    hdr_text_col->addWidget(hdr_title);
    hdr_text_col->addLayout(hdr_sub_row);
    ctr_hdr_l->addLayout(hdr_text_col);
    ctr_hdr_l->addStretch();

    // Avatar in header (Idle/Thinking/Responding)
    auto* main_avatar = new AiAvatarWidget(38, ctr_hdr);
    ai_avatar_widget_ = main_avatar;
    ctr_hdr_l->addWidget(main_avatar);

    ctr_hdr_l->addWidget(MakeIconBtn(AiPageIcon::Bell, ctr_hdr));
    ctr_hdr_l->addWidget(MakeIconBtn(AiPageIcon::MoreHorizontal, ctr_hdr));
    center_l->addWidget(ctr_hdr);

    // Chat scroll area
    ai_chat_scroll_ = new QScrollArea(center);
    ai_chat_scroll_->setWidgetResizable(true);
    ai_chat_scroll_->setFrameShape(QFrame::NoFrame);
    ai_chat_scroll_->setStyleSheet(
        "QScrollArea { background: transparent; border: none; }"
        "QScrollBar:vertical { background:transparent; width:4px; margin:4px 2px; }"
        "QScrollBar::handle:vertical { background:rgba(255,170,90,50); border-radius:2px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }");
    ai_chat_widget_ = new QWidget();
    ai_chat_widget_->setStyleSheet("background: transparent;");
    ai_chat_scroll_->viewport()->setStyleSheet("background: transparent;");
    ai_chat_layout_ = new QVBoxLayout(ai_chat_widget_);
    ai_chat_layout_->setContentsMargins(0,16,0,16);
    ai_chat_layout_->setSpacing(8);
    ai_chat_layout_->addStretch();
    ai_chat_scroll_->setWidget(ai_chat_widget_);
    center_l->addWidget(ai_chat_scroll_, 1);

    // Input area
    auto* input_area = new QWidget(center);
    input_area->setFixedHeight(108);
    input_area->setStyleSheet(
        "QWidget { background:rgba(14,9,4,234);"
        " border-top: 1px solid rgba(255,170,90,18); }");
    auto* input_area_l = new QVBoxLayout(input_area);
    input_area_l->setContentsMargins(16,10,16,10);
    input_area_l->setSpacing(6);

    // Input container
    auto* input_container = new QFrame(input_area);
    input_container->setStyleSheet(
        "QFrame { background:rgba(26,18,12,242);"
        " border:1px solid rgba(255,170,90,36);"
        " border-radius:14px; }");
    auto* input_container_l = new QVBoxLayout(input_container);
    input_container_l->setContentsMargins(14,8,10,6);
    input_container_l->setSpacing(4);

    ai_input_edit_ = new QLineEdit(input_container);
    ai_input_edit_->setPlaceholderText(
        QString::fromUtf8("Ask about threats, malware, detections, security..."));
    ai_input_edit_->setEnabled(false);
    ai_input_edit_->setMinimumHeight(30);
    ai_input_edit_->setStyleSheet(
        "QLineEdit { background:transparent; border:none; color:#ffffff;"
        " font-size:10.5pt; padding:2px 4px; }"
        "QLineEdit:disabled { color:rgba(255,255,255,60); }");
    input_container_l->addWidget(ai_input_edit_);

    // Bottom toolbar
    auto* toolbar = new QWidget(input_container);
    toolbar->setStyleSheet(
        "QWidget { border-top:1px solid rgba(255,170,90,18); background:transparent; }");
    auto* toolbar_l = new QHBoxLayout(toolbar);
    toolbar_l->setContentsMargins(0,4,0,0);
    toolbar_l->setSpacing(4);

    auto* inject_btn = new QPushButton(toolbar);
    inject_btn->setFixedHeight(26);
    inject_btn->setStyleSheet(
        "QPushButton { background:rgba(255,122,0,20); color:rgba(255,155,61,0.85);"
        " border:1px solid rgba(255,122,0,46); border-radius:8px;"
        " padding:2px 10px; font-size:9pt; }"
        "QPushButton:hover { background:rgba(255,122,0,40); }");
    {
        auto* il = new QHBoxLayout(inject_btn);
        il->setContentsMargins(6,0,6,0); il->setSpacing(5);
        il->addWidget(new AiPageIcon(AiPageIcon::Scan, 11, QColor(0xFF,0x9B,0x3D), inject_btn));
        auto* il2 = new QLabel(QString::fromUtf8("Inject Detections"), inject_btn);
        il2->setStyleSheet("color:rgba(255,155,61,0.85); font-size:9pt; background:transparent;");
        il->addWidget(il2);
    }
    toolbar_l->addWidget(inject_btn);

    auto* clear_btn = new QPushButton(toolbar);
    clear_btn->setFixedHeight(26);
    clear_btn->setStyleSheet(
        "QPushButton { background:rgba(235,59,90,0); color:rgba(235,100,130,0.6);"
        " border:1px solid rgba(235,59,90,30); border-radius:8px;"
        " padding:2px 10px; font-size:9pt; }"
        "QPushButton:hover { background:rgba(235,59,90,30); color:#ff6b8a; }");
    {
        auto* il = new QHBoxLayout(clear_btn);
        il->setContentsMargins(6,0,6,0); il->setSpacing(5);
        il->addWidget(new AiPageIcon(AiPageIcon::RefreshCw, 11, QColor(0xEB,0x5A,0x6A), clear_btn));
        auto* il2 = new QLabel("Clear", clear_btn);
        il2->setStyleSheet("color:rgba(235,100,130,0.6); font-size:9pt; background:transparent;");
        il->addWidget(il2);
    }
    toolbar_l->addWidget(clear_btn);
    toolbar_l->addStretch();

    toolbar_l->addWidget(MakeIconBtn(AiPageIcon::Paperclip, toolbar));
    toolbar_l->addWidget(MakeIconBtn(AiPageIcon::Mic, toolbar));

    ai_stop_btn_ = new QPushButton(toolbar);
    ai_stop_btn_->setFixedSize(30,26);
    ai_stop_btn_->setVisible(false);
    ai_stop_btn_->setStyleSheet(
        "QPushButton { background:rgba(235,59,90,46); color:#ff5577;"
        " border:1px solid rgba(235,59,90,90); border-radius:7px; font-size:10pt; }"
        "QPushButton:hover { background:rgba(235,59,90,90); }");
    ai_stop_btn_->setText("\xe2\x8f\xb9");
    toolbar_l->addWidget(ai_stop_btn_);

    ai_send_btn_ = new QPushButton(toolbar);
    ai_send_btn_->setFixedSize(72,26);
    ai_send_btn_->setEnabled(false);
    ai_send_btn_->setStyleSheet(
        "QPushButton { background:rgba(255,122,0,30); color:rgba(255,255,255,80);"
        " border:1px solid rgba(255,122,0,60); border-radius:8px;"
        " font-size:9.5pt; font-weight:700; }"
        "QPushButton:enabled { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        " stop:0 #FF7A00, stop:1 #E55A00); color:#fff;"
        " border-color:rgba(255,122,0,120); }"
        "QPushButton:enabled:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        " stop:0 #FF9B3D, stop:1 #FF7A00); }");
    {
        auto* sl = new QHBoxLayout(ai_send_btn_);
        sl->setContentsMargins(6,0,6,0); sl->setSpacing(4);
        auto* sl_txt = new QLabel("Send", ai_send_btn_);
        sl_txt->setStyleSheet("color:inherit; font-size:9.5pt; font-weight:700; background:transparent;");
        sl->addWidget(sl_txt);
        sl->addWidget(new AiPageIcon(AiPageIcon::ChevronRight, 11, Qt::white, ai_send_btn_));
    }
    toolbar_l->addWidget(ai_send_btn_);
    input_container_l->addWidget(toolbar);
    input_area_l->addWidget(input_container);

    // Footer note
    auto* footer_note = new QLabel(
        "TeoAV Assistant may make mistakes. Verify critical security decisions independently.",
        input_area);
    footer_note->setAlignment(Qt::AlignCenter);
    footer_note->setStyleSheet("color:#33261A; font-size:8pt; background:transparent;");
    input_area_l->addWidget(footer_note);
    center_l->addWidget(input_area);
    root->addWidget(center, 1);

    // ═══════════════════════════════════════════════════════════════════════════
    // RIGHT PANEL (280px)
    // ═══════════════════════════════════════════════════════════════════════════
    auto* right_panel = new QWidget(page);
    right_panel->setFixedWidth(280);
    right_panel->setStyleSheet(
        "QWidget { background:rgba(14,9,4,247);"
        " border-left:1px solid rgba(255,170,90,18); }");

    auto* rp_scroll = new QScrollArea(right_panel);
    rp_scroll->setWidgetResizable(true);
    rp_scroll->setFrameShape(QFrame::NoFrame);
    rp_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    rp_scroll->setStyleSheet(
        "QScrollArea { background:transparent; border:none; }"
        "QScrollBar:vertical { background:transparent; width:3px; margin:0; }"
        "QScrollBar::handle:vertical { background:rgba(255,170,90,40); border-radius:1px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }");
    auto* rp_inner = new QWidget(rp_scroll);
    rp_inner->setStyleSheet("background:transparent;");
    auto* rp_l = new QVBoxLayout(rp_inner);
    rp_l->setContentsMargins(12,14,12,14);
    rp_l->setSpacing(10);

    // Helper: make a card
    auto makeCard = [&](QColor border_tint) -> QFrame* {
        auto* card = new QFrame(rp_inner);
        card->setStyleSheet(QString(
            "QFrame { background:rgba(26,18,12,230);"
            " border:1px solid rgba(%1,%2,%3,36);"
            " border-radius:12px; }")
            .arg(border_tint.red()).arg(border_tint.green()).arg(border_tint.blue()));
        return card;
    };

    // ── Model loading card ────────────────────────────────────────────────────
    auto* model_card = makeCard(QColor(255,122,0));
    auto* model_card_l = new QVBoxLayout(model_card);
    model_card_l->setContentsMargins(12,10,12,10);
    model_card_l->setSpacing(6);

    auto* model_hdr_row = new QHBoxLayout();
    model_hdr_row->setSpacing(6);
    model_hdr_row->addWidget(new AiPageIcon(AiPageIcon::Zap, 12, QColor(0xFF,0x9B,0x3D), model_card));
    auto* model_hdr_lbl = new QLabel("MODEL", model_card);
    model_hdr_lbl->setStyleSheet(
        "color:#6B5B4E; font-size:8.5pt; font-weight:700;"
        " letter-spacing:1px; background:transparent;");
    model_hdr_row->addWidget(model_hdr_lbl);
    model_hdr_row->addStretch();
    model_card_l->addLayout(model_hdr_row);

    auto* inline_model_edit = new QLineEdit(model_card);
    inline_model_edit->setPlaceholderText("path/to/model.gguf");
    inline_model_edit->setStyleSheet(
        "QLineEdit { background:rgba(0,0,0,80); border:1px solid rgba(255,170,90,36);"
        " border-radius:7px; padding:4px 8px; color:rgba(255,255,255,180);"
        " font-size:8pt; }"
        "QLineEdit:focus { border-color:rgba(255,122,0,120); }");
    if (!config_.ai_model_path.empty())
        inline_model_edit->setText(QString::fromUtf8(config_.ai_model_path.c_str()));
    model_card_l->addWidget(inline_model_edit);

    // First-run guidance for anyone who downloaded the app without a model
    // on hand -- otherwise this card just looks broken/incomplete. Every
    // other page works fully without a model loaded; this hint says so
    // explicitly so it doesn't read as a missing feature.
    if (config_.ai_model_path.empty()) {
        auto* model_hint = new QLabel(QString::fromUtf8(
            "No model yet? Download any chat GGUF model (e.g. search "
            "\"Qwen2.5-3B-Instruct-GGUF\" on huggingface.co, Q4_K_M size is a "
            "good default) and pick the .gguf file above. Everything else in "
            "AvSuite works fully without this -- it only powers this AI page."),
            model_card);
        model_hint->setWordWrap(true);
        model_hint->setStyleSheet(
            "color:rgba(255,255,255,110); font-size:7.5pt; background:transparent;");
        model_card_l->addWidget(model_hint);
    }

    auto* model_btns_row = new QHBoxLayout();
    model_btns_row->setSpacing(6);
    auto* browse_btn = new QPushButton(QString::fromUtf8("\xf0\x9f\x93\x82"), model_card);
    browse_btn->setFixedSize(34,28);
    browse_btn->setStyleSheet(
        "QPushButton { background:rgba(255,122,0,20); border:1px solid rgba(255,122,0,50);"
        " border-radius:7px; font-size:10pt; color:#fff; }"
        "QPushButton:hover { background:rgba(255,122,0,50); }");
    model_btns_row->addWidget(browse_btn);
    auto* load_btn = new QPushButton(QString::fromUtf8("Load Model"), model_card);
    load_btn->setStyleSheet(
        "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        " stop:0 #FF7A00, stop:1 #E55A00);"
        " color:#fff; font-weight:700; font-size:9pt;"
        " border-radius:7px; padding:4px 10px;"
        " border:1px solid rgba(255,122,0,120); }"
        "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        " stop:0 #FF9B3D, stop:1 #FF7A00); }"
        "QPushButton:disabled { background:rgba(255,255,255,18);"
        " color:rgba(255,255,255,50); border-color:transparent; }");
    model_btns_row->addWidget(load_btn, 1);
    model_card_l->addLayout(model_btns_row);

    ai_status_label_ = new QLabel(
        QString::fromUtf8("\xe2\x97\x8f Not loaded"), model_card);
    ai_status_label_->setStyleSheet(
        "color:rgba(255,255,255,90); font-size:8pt; font-style:italic; background:transparent;");
    model_card_l->addWidget(ai_status_label_);
    rp_l->addWidget(model_card);

    // ── System Status card ────────────────────────────────────────────────────
    auto* status_card = makeCard(QColor(74,222,128));
    auto* status_card_l = new QVBoxLayout(status_card);
    status_card_l->setContentsMargins(12,10,12,10);
    status_card_l->setSpacing(6);

    auto* sc_hdr = new QHBoxLayout();
    sc_hdr->setSpacing(6);
    auto* sc_icon_box = new QFrame(status_card);
    sc_icon_box->setFixedSize(26,26);
    sc_icon_box->setStyleSheet(
        "QFrame { background:rgba(74,222,128,23); border:1px solid rgba(74,222,128,60);"
        " border-radius:7px; }");
    auto* sc_icon_box_l = new QVBoxLayout(sc_icon_box);
    sc_icon_box_l->setContentsMargins(5,5,5,5);
    sc_icon_box_l->addWidget(
        new AiPageIcon(AiPageIcon::ShieldCheck, 14, QColor(0x4A,0xDE,0x80), sc_icon_box));
    sc_hdr->addWidget(sc_icon_box);
    auto* sc_title = new QLabel("SYSTEM STATUS", status_card);
    sc_title->setStyleSheet(
        "color:#6B5B4E; font-size:8.5pt; font-weight:700;"
        " letter-spacing:1px; background:transparent;");
    sc_hdr->addWidget(sc_title);
    sc_hdr->addStretch();
    status_card_l->addLayout(sc_hdr);

    auto* sc_main_row = new QHBoxLayout();
    sc_main_row->setSpacing(8);
    auto* sc_dot = new QLabel(status_card);
    sc_dot->setFixedSize(10,10);
    sc_dot->setStyleSheet(
        "QLabel { background:#4ADE80; border-radius:5px; border:none; }");
    sc_main_row->addWidget(sc_dot);
    auto* sc_status = new QLabel("Protected", status_card);
    sc_status->setStyleSheet(
        "color:#ffffff; font-size:12pt; font-weight:700; background:transparent;");
    sc_main_row->addWidget(sc_status);
    sc_main_row->addStretch();
    status_card_l->addLayout(sc_main_row);

    auto* sc_sub = new QLabel("TeoAV Engine v4.2 " "\xc2\xb7" " Active", status_card);
    sc_sub->setStyleSheet(
        "color:#6B5B4E; font-size:8.5pt; font-family:Consolas,monospace;"
        " background:transparent;");
    status_card_l->addWidget(sc_sub);
    rp_l->addWidget(status_card);

    // ── Realtime Context card ─────────────────────────────────────────────────
    auto* ctx_card = makeCard(QColor(255,170,90));
    auto* ctx_card_l = new QVBoxLayout(ctx_card);
    ctx_card_l->setContentsMargins(12,10,12,10);
    ctx_card_l->setSpacing(6);

    auto* ctx_hdr = new QHBoxLayout();
    ctx_hdr->setSpacing(6);
    ctx_hdr->addWidget(new AiPageIcon(AiPageIcon::Activity, 12, QColor(0xFF,0x9B,0x3D), ctx_card));
    auto* ctx_title = new QLabel("REALTIME CONTEXT", ctx_card);
    ctx_title->setStyleSheet(
        "color:#6B5B4E; font-size:8.5pt; font-weight:700;"
        " letter-spacing:1px; background:transparent;");
    ctx_hdr->addWidget(ctx_title);
    ctx_hdr->addStretch();
    ctx_card_l->addLayout(ctx_hdr);

    // Helper: mini stat row
    auto makeStatRow = [&](const QString& label, const QString& value, QColor val_color) -> QHBoxLayout* {
        auto* row = new QHBoxLayout();
        row->setSpacing(4);
        auto* lbl = new QLabel(label + ":", ctx_card);
        lbl->setStyleSheet("color:#6B5B4E; font-size:9pt; background:transparent;");
        auto* val = new QLabel(value, ctx_card);
        val->setStyleSheet(
            QString("color:%1; font-size:9pt; font-weight:600; background:transparent;")
                .arg(val_color.name()));
        row->addWidget(lbl);
        row->addStretch();
        row->addWidget(val);
        return row;
    };

    const auto recent = engine_->RecentDetections(1000);
    const int det_count = static_cast<int>(recent.size());
    const int qcount = static_cast<int>(engine_->RecentDetections(1000).size()); // reuse

    ctx_card_l->addLayout(makeStatRow("Realtime Protection", "ACTIVE", QColor(0x4A,0xDE,0x80)));
    ctx_card_l->addLayout(makeStatRow("Threats Today",
        QString::number(det_count),
        det_count > 0 ? QColor(0xFF,0x5A,0x6A) : QColor(0x4A,0xDE,0x80)));
    ctx_card_l->addLayout(makeStatRow("Driver Status", "LOADED", QColor(0x4A,0xDE,0x80)));
    rp_l->addWidget(ctx_card);

    // ── Quick Actions card ────────────────────────────────────────────────────
    auto* qa_card = makeCard(QColor(255,122,0));
    auto* qa_card_l = new QVBoxLayout(qa_card);
    qa_card_l->setContentsMargins(12,10,12,10);
    qa_card_l->setSpacing(6);

    auto* qa_hdr = new QHBoxLayout();
    qa_hdr->setSpacing(6);
    qa_hdr->addWidget(new AiPageIcon(AiPageIcon::Sparkles, 12, QColor(0xFF,0x9B,0x3D), qa_card));
    auto* qa_title = new QLabel("QUICK ACTIONS", qa_card);
    qa_title->setStyleSheet(
        "color:#6B5B4E; font-size:8.5pt; font-weight:700;"
        " letter-spacing:1px; background:transparent;");
    qa_hdr->addWidget(qa_title);
    qa_hdr->addStretch();
    qa_card_l->addLayout(qa_hdr);

    auto makeQABtn = [&](AiPageIcon::Type ico, const QString& label,
                          const QString& prompt_text) -> QPushButton* {
        auto* btn = new QPushButton(qa_card);
        btn->setFixedHeight(52);
        btn->setStyleSheet(
            "QPushButton { background:rgba(0,0,0,60); border:1px solid rgba(255,170,90,23);"
            " border-radius:10px; }"
            "QPushButton:hover { background:rgba(255,122,0,23);"
            " border-color:rgba(255,122,0,60); }");
        auto* bl = new QVBoxLayout(btn);
        bl->setContentsMargins(10,8,10,8);
        bl->setSpacing(4);
        auto* ico_box = new QFrame(btn);
        ico_box->setFixedSize(28,28);
        ico_box->setStyleSheet(
            "QFrame { background:rgba(255,122,0,23); border:1px solid rgba(255,122,0,50);"
            " border-radius:8px; }");
        auto* ico_box_l = new QVBoxLayout(ico_box);
        ico_box_l->setContentsMargins(6,6,6,6);
        ico_box_l->addWidget(new AiPageIcon(ico, 14, QColor(0xFF,0x9B,0x3D), ico_box));
        bl->addWidget(ico_box);
        auto* lbl = new QLabel(label, btn);
        lbl->setStyleSheet(
            "color:#C7B6A2; font-size:9pt; background:transparent;");
        bl->addWidget(lbl);
        if (!prompt_text.isEmpty()) {
            connect(btn, &QPushButton::clicked, this,
                    [aiPrefill, prompt_text] { aiPrefill(prompt_text); });
        }
        return btn;
    };

    auto* qa_grid_row1 = new QHBoxLayout();
    auto* qa_grid_row2 = new QHBoxLayout();
    qa_grid_row1->setSpacing(6);
    qa_grid_row2->setSpacing(6);
    auto* qa_analyze = makeQABtn(AiPageIcon::FileSearch, "Analyze File", "");
    auto* qa_explain = makeQABtn(AiPageIcon::Eye, "Explain Detection",
        "Please explain this detection and what it means: ");
    auto* qa_yara = makeQABtn(AiPageIcon::Code, "Generate YARA",
        "Please generate a YARA rule to detect this threat pattern: ");
    auto* qa_report = makeQABtn(AiPageIcon::FileText, "Create Report", "");
    connect(qa_analyze, &QPushButton::clicked, this, doAnalyzeFile);
    connect(qa_report,  &QPushButton::clicked, this, doThreatReport);
    qa_grid_row1->addWidget(qa_analyze);
    qa_grid_row1->addWidget(qa_explain);
    qa_grid_row2->addWidget(qa_yara);
    qa_grid_row2->addWidget(qa_report);
    qa_card_l->addLayout(qa_grid_row1);
    qa_card_l->addLayout(qa_grid_row2);
    rp_l->addWidget(qa_card);

    // ── AI Suggestions card ───────────────────────────────────────────────────
    auto* sug_card = makeCard(QColor(255,122,0));
    auto* sug_card_l = new QVBoxLayout(sug_card);
    sug_card_l->setContentsMargins(12,10,12,10);
    sug_card_l->setSpacing(6);

    auto* sug_hdr = new QHBoxLayout();
    sug_hdr->setSpacing(6);
    sug_hdr->addWidget(new AiPageIcon(AiPageIcon::Sparkles, 12, QColor(0xFF,0x9B,0x3D), sug_card));
    auto* sug_title = new QLabel("AI SUGGESTIONS", sug_card);
    sug_title->setStyleSheet(
        "color:#6B5B4E; font-size:8.5pt; font-weight:700;"
        " letter-spacing:1px; background:transparent;");
    sug_hdr->addWidget(sug_title);
    sug_hdr->addStretch();
    sug_card_l->addLayout(sug_hdr);

    // Each suggestion is a real, clickable action -- not decoration. Uses a
    // QPushButton (like the RECENT items) so clicks fire and hover works.
    auto makeSugItem = [&](AiPageIcon::Type ico, QColor ico_color,
                            const QString& text, const QString& meta,
                            std::function<void()> onClick) -> QWidget* {
        auto* item = new QPushButton(sug_card);
        item->setCursor(Qt::PointingHandCursor);
        item->setMinimumHeight(48);
        item->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
        item->setStyleSheet(
            "QPushButton { text-align:left; background:transparent;"
            " border-radius:8px; border:1px solid transparent; }"
            "QPushButton:hover { background:rgba(255,122,0,15);"
            " border-color:rgba(255,122,0,36); }");
        QObject::connect(item, &QPushButton::clicked, item,
                         [onClick] { if (onClick) onClick(); });
        auto* il = new QHBoxLayout(item);
        il->setContentsMargins(6,6,6,6);
        il->setSpacing(8);
        il->addWidget(new AiPageIcon(ico, 13, ico_color, item), 0, Qt::AlignTop);
        auto* tc = new QVBoxLayout();
        tc->setSpacing(2);
        auto* txt = new QLabel(text, item);
        txt->setStyleSheet("color:#C7B6A2; font-size:9.5pt; background:transparent;");
        txt->setWordWrap(true);
        auto* meta_lbl = new QLabel(meta, item);
        meta_lbl->setStyleSheet("color:#4A3B30; font-size:8.5pt; background:transparent;");
        meta_lbl->setWordWrap(true);
        tc->addWidget(txt);
        tc->addWidget(meta_lbl);
        il->addLayout(tc, 1);
        return item;
    };

    // Suggestion 1: real detection count + opens the threat report dialog.
    const QString det_meta = det_count > 0
        ? QString::fromUtf8("%1 detection(s) on record").arg(det_count)
        : QString::fromUtf8("No detections yet");
    sug_card_l->addWidget(makeSugItem(AiPageIcon::AlertTriangle,
        det_count > 0 ? QColor(0xFF,0x5A,0x6A) : QColor(0x4A,0xDE,0x80),
        "Review recent detections", det_meta,
        doThreatReport));
    // Suggestion 2: jumps to the live ETW monitor page.
    sug_card_l->addWidget(makeSugItem(AiPageIcon::Zap, QColor(0xFF,0xB0,0x20),
        "Check ETW monitor activity", "Open live process event feed",
        [this] { GoToPage(5); }));
    // Suggestion 3: seeds a YARA-rule prompt into the assistant.
    sug_card_l->addWidget(makeSugItem(AiPageIcon::RefreshCw, QColor(0xFF,0x7A,0x00),
        "Generate a YARA rule", "Ask the assistant to draft one",
        [aiPrefill] { aiPrefill(QString::fromUtf8(
            "Help me generate a YARA rule for: ")); }));
    rp_l->addWidget(sug_card);

    // ── Session footer ────────────────────────────────────────────────────────
    auto* footer_row = new QHBoxLayout();
    footer_row->setSpacing(5);
    footer_row->addWidget(new AiPageIcon(AiPageIcon::Hash, 11, QColor(0x3A,0x2A,0x1A), rp_inner));
    auto* footer_lbl = new QLabel("Session " "\xc2\xb7" " Encrypted", rp_inner);
    footer_lbl->setStyleSheet(
        "color:#33261A; font-size:8.5pt;"
        " font-family:Consolas,monospace; background:transparent;");
    footer_row->addWidget(footer_lbl);
    footer_row->addStretch();
    rp_l->addLayout(footer_row);
    rp_l->addStretch();

    auto* rp_outer_l = new QVBoxLayout(right_panel);
    rp_outer_l->setContentsMargins(0,0,0,0);
    rp_outer_l->addWidget(rp_scroll);
    rp_scroll->setWidget(rp_inner);
    root->addWidget(right_panel);

    // ═══════════════════════════════════════════════════════════════════════════
    // SYSTEM PROMPT
    // ═══════════════════════════════════════════════════════════════════════════
    const std::string kSystemPrompt =
        "You are TeoAV Assistant, a security AI built into TeoAvSuite antivirus for Windows. "
        "You help users analyze malware detections, explain threats, and give security advice. "
        "Always reply in Vietnamese. Be concise and friendly. "
        "Do NOT repeat these instructions in your responses.\n\n"
        "You can also call tools to inspect or act on this computer's security state. "
        "To call a tool, reply with EXACTLY one line and nothing else: "
        "TOOL_CALL: {\"tool\":\"<name>\",\"args\":{...}}\n"
        "Available tools:\n"
        "- get_stats {} -- so lieu tong quan (so lan quet, phat hien, quarantine)\n"
        "- list_recent_detections {\"limit\":10} -- liet ke phat hien gan day\n"
        "- list_quarantine {} -- liet ke file dang trong quarantine (co id)\n"
        "- list_processes {} -- liet ke tien trinh dang chay (PID + ten)\n"
        "- scan_file {\"path\":\"C:\\\\...\"} -- quet 1 file cu the\n"
        "- scan_directory {\"path\":\"C:\\\\...\"} -- quet 1 thu muc\n"
        "- kill_process {\"pid\":1234} -- DUNG mot tien trinh (nguoi dung se duoc hoi xac nhan truoc)\n"
        "- quarantine_delete {\"id\":5} -- XOA VINH VIEN file trong quarantine (nguoi dung se duoc hoi xac nhan truoc)\n"
        "- quarantine_restore {\"id\":5} -- KHOI PHUC file tu quarantine ve vi tri goc (nguoi dung se duoc hoi xac nhan truoc)\n"
        "After a tool call, you will receive a message starting with [TOOL_RESULT ...] containing "
        "the result -- use it to answer the user's original question in Vietnamese, in plain text "
        "(no further TOOL_CALL unless genuinely needed for a follow-up step). "
        "Only call a tool when the user's request actually needs current system state or an action "
        "-- do not call a tool just to answer general security questions.";

    // ═══════════════════════════════════════════════════════════════════════════
    // addBubble helper — adds bubble with fade-in animation
    // ═══════════════════════════════════════════════════════════════════════════
    auto addBubble = [this](const QString& text, Qt::Alignment align,
                             bool is_dots = false) -> QLabel* {
        // Remove trailing stretch
        auto* stretchItem = ai_chat_layout_->itemAt(ai_chat_layout_->count()-1);
        if (stretchItem && stretchItem->spacerItem()) {
            ai_chat_layout_->removeItem(stretchItem);
            delete stretchItem;
        }
        auto* row = new QWidget(ai_chat_widget_);
        row->setStyleSheet("background:transparent;");
        auto* row_l = new QHBoxLayout(row);
        row_l->setContentsMargins(16,3,16,3);
        row_l->setSpacing(10);

        QLabel* lbl = nullptr;

        if (align == Qt::AlignRight) {
            auto* bubble = new QFrame(row);
            bubble->setFrameShape(QFrame::NoFrame);
            bubble->setMaximumWidth(580);
            bubble->setStyleSheet(
                "QFrame { background:rgba(36,23,14,242);"
                " border:1px solid rgba(255,170,90,36);"
                " border-radius:18px 18px 4px 18px; }");
            auto* bl = new QVBoxLayout(bubble);
            bl->setContentsMargins(14,10,14,10);
            lbl = new QLabel(text, bubble);
            lbl->setObjectName("msg_text");
            lbl->setWordWrap(true);
            lbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
            lbl->setStyleSheet("color:#ffffff; font-size:10pt; background:transparent;");
            lbl->setFont(QFont("Segoe UI",10));
            bl->addWidget(lbl);

            auto* icon_box = new QFrame(row);
            icon_box->setFixedSize(36,36);
            icon_box->setStyleSheet(
                "QFrame { background:rgba(255,255,255,18);"
                " border:1px solid rgba(255,255,255,23); border-radius:10px; }");
            auto* ib_l = new QVBoxLayout(icon_box);
            ib_l->setContentsMargins(9,9,9,9);
            ib_l->addWidget(new AiPageIcon(AiPageIcon::User,16,QColor(0xC7,0xB6,0xA2),icon_box));

            row_l->addStretch();
            row_l->addWidget(bubble);
            row_l->addWidget(icon_box, 0, Qt::AlignTop);
        } else {
            auto* bot_box = new QFrame(row);
            bot_box->setFixedSize(36,36);
            bot_box->setStyleSheet(
                "QFrame { background:rgba(255,122,0,33);"
                " border:1px solid rgba(255,122,0,56); border-radius:10px; }");
            auto* bb_l = new QVBoxLayout(bot_box);
            bb_l->setContentsMargins(9,9,9,9);
            bb_l->addWidget(new AiPageIcon(AiPageIcon::Bot,16,QColor(0xFF,0x7A,0x00),bot_box));

            auto* bubble = new QFrame(row);
            bubble->setFrameShape(QFrame::NoFrame);
            bubble->setMaximumWidth(580);
            bubble->setStyleSheet(
                "QFrame { background:rgba(26,18,12,216);"
                " border:1px solid rgba(255,170,90,23);"
                " border-radius:4px 18px 18px 18px; }");
            auto* bl = new QVBoxLayout(bubble);
            bl->setContentsMargins(14,10,14,10);

            if (is_dots) {
                auto* dots = new AiThinkingDots(bubble);
                bl->addWidget(dots);
                lbl = nullptr;
            } else {
                lbl = new QLabel(text, bubble);
                lbl->setObjectName("msg_text");
                lbl->setWordWrap(true);
                lbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
                lbl->setStyleSheet("color:#E8D8C8; font-size:10pt; background:transparent;");
                lbl->setFont(QFont("Segoe UI",10));
                bl->addWidget(lbl);
            }
            row_l->addWidget(bot_box, 0, Qt::AlignTop);
            row_l->addWidget(bubble, 1);
            row_l->addStretch();
        }

        ai_chat_layout_->addWidget(row);
        ai_chat_layout_->addStretch();

        // Fade-in animation
        auto* eff = new QGraphicsOpacityEffect(row);
        eff->setOpacity(0.0);
        row->setGraphicsEffect(eff);
        auto* anim = new QPropertyAnimation(eff, "opacity", row);
        anim->setDuration(280);
        anim->setStartValue(0.0);
        anim->setEndValue(1.0);
        anim->setEasingCurve(QEasingCurve::OutCubic);
        anim->start(QAbstractAnimation::DeleteWhenStopped);

        QTimer::singleShot(0, this, [this] {
            ai_chat_scroll_->verticalScrollBar()->setValue(
                ai_chat_scroll_->verticalScrollBar()->maximum());
        });
        return lbl;
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // WIRE: Browse
    // ═══════════════════════════════════════════════════════════════════════════
    connect(browse_btn, &QPushButton::clicked, this, [inline_model_edit, this] {
        const QString p = QFileDialog::getOpenFileName(
            this,
            QString::fromUtf8("Ch\xe1\xbb\x8dn model GGUF"),
            inline_model_edit->text(),
            QString::fromUtf8("GGUF model (*.gguf);;T\xe1\xba\xa5t c\xe1\xba\xa3 (*.*)"));
        if (!p.isEmpty()) inline_model_edit->setText(p);
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // WIRE: Load model
    // ═══════════════════════════════════════════════════════════════════════════
    connect(load_btn, &QPushButton::clicked, this,
            [this, load_btn, inline_model_edit, kSystemPrompt, addBubble] {
        const std::string model_path = inline_model_edit->text().toStdString();
        if (model_path.empty()) {
            addBubble(QString::fromUtf8(
                "\xe2\x9a\xa0 Please select a .gguf model file first."),
                Qt::AlignLeft);
            return;
        }
        config_.ai_model_path = model_path;
        if (!config_.config_file_path.empty())
            config_.SaveToFile(config_.config_file_path);

        load_btn->setEnabled(false);
        ai_status_label_->setText(
            QString::fromUtf8("\xe2\x8f\xb3 Loading..."));
        ai_status_label_->setStyleSheet(
            "color:#FF9B3D; font-size:8pt; font-style:italic; background:transparent;");
        static_cast<AiAvatarWidget*>(ai_avatar_widget_)
            ->setState(AiAvatarWidget::State::Thinking);

        std::thread([this, model_path, load_btn, kSystemPrompt, addBubble] {
            std::string err;
            try {
                ai_assistant_ = std::make_unique<avai::LlmAssistant>(model_path, 4096, 0);
                ai_history_.clear();
                ai_history_.push_back({"system", kSystemPrompt});
            } catch (const std::exception& e) { err = e.what(); }

            if (!AppQuitting().load()) {
                QMetaObject::invokeMethod(this, [this, err, load_btn, addBubble] {
                static_cast<AiAvatarWidget*>(ai_avatar_widget_)
                    ->setState(AiAvatarWidget::State::Idle);
                if (!err.empty()) {
                    ai_status_label_->setText(
                        QString::fromUtf8("\xe2\x9c\x97 Error"));
                    ai_status_label_->setStyleSheet(
                        "color:#FF5A6A; font-size:8pt; background:transparent;");
                    addBubble(
                        QString::fromUtf8("\xe2\x9a\xa0 ") +
                        QString::fromUtf8(err.c_str()),
                        Qt::AlignLeft);
                    load_btn->setEnabled(true);
                    return;
                }
                const auto s = config_.ai_model_path.find_last_of("/\\");
                const std::string name = (s != std::string::npos)
                    ? config_.ai_model_path.substr(s+1) : config_.ai_model_path;
                ai_status_label_->setText(
                    QString::fromUtf8("\xe2\x9c\x93 ") +
                    QString::fromUtf8(name.c_str()));
                ai_status_label_->setStyleSheet(
                    "color:#4ADE80; font-size:8pt; background:transparent;");
                ai_input_edit_->setEnabled(true);
                ai_send_btn_->setEnabled(true);
                addBubble(
                    QString::fromUtf8(
                        "Xin ch\xc3\xa0o! T\xc3\xb4i l\xc3\xa0 TeoAV Assistant\n\n"
                        "T\xc3\xb4i c\xc3\xb3 th\xe1\xbb\x83 gi\xc3\xba"
                        "p b\xe1\xba\xa1n:\n"
                        "\xe2\x80\xa2 Ph\xc3\xa2n t\xc3\xad"
                        "ch malware v\xc3\xa0 ph\xc3\xa1t hi\xe1\xbb\x87n\n"
                        "\xe2\x80\xa2 T\xe1\xba\xa1o rule YARA\n"
                        "\xe2\x80\xa2 T\xc6\xb0 v\xe1\xba\xa5n b\xe1\xba\xa3o m\xe1\xba\xadt\n\n"
                        "S\xe1\xbb\xad d\xe1\xbb\xa5ng Quick Actions b\xc3\xaan ph\xe1\xba\xa3i "
                        "ho\xe1\xba\xb7""c h\xe1\xbb\x8fi b\xe1\xba\xa5t k\xe1\xbb\xb3 \xc4\x91i\xe1\xbb\x81u g\xc3\xac!"),
                    Qt::AlignLeft);
                }, Qt::QueuedConnection);
            }
        }).detach();
    });

    // Agentic tool loop lives in main_window_ai_agent.cpp (MainWindow::
    // RunAiGenerationTurn / HandleAiToolCall / ContinueAiWithToolResult),
    // deliberately kept out of this file: this TU already forces /Od for an
    // MSVC 14.44 ICE (see CMakeLists.txt), and stacking a mutually-recursive
    // shared_ptr<std::function<...>> chain on top of that reliably crashed
    // CL.exe (0xC0000005 / 0xC0000409, 3/3 attempts) even after retries that
    // fix transient issues elsewhere in this codebase. A fresh TU with plain
    // member functions (no nested-lambda self-reference) compiles clean.
    ai_add_bubble_ = addBubble;

    auto sendMessage = [this] {
        if (ai_sending_ || !ai_assistant_) return;
        const QString user_text = ai_input_edit_->text().trimmed();
        if (user_text.isEmpty()) return;

        ai_sending_ = true;
        ai_tool_loop_count_ = 0;
        ai_input_edit_->clear();
        ai_send_btn_->setEnabled(false);
        ai_input_edit_->setEnabled(false);
        ai_stop_btn_->setVisible(true);
        static_cast<AiAvatarWidget*>(ai_avatar_widget_)
            ->setState(AiAvatarWidget::State::Thinking);

        ai_add_bubble_(user_text, Qt::AlignRight, false);
        ai_history_.push_back({"user", user_text.toStdString()});
        if (ai_history_.size() > 11)
            ai_history_.erase(ai_history_.begin()+1, ai_history_.begin()+3);

        RunAiGenerationTurn();
    };

    connect(ai_send_btn_,   &QPushButton::clicked,     this, sendMessage);
    connect(ai_input_edit_, &QLineEdit::returnPressed, this, sendMessage);

    // ═══════════════════════════════════════════════════════════════════════════
    // WIRE: Stop
    // ═══════════════════════════════════════════════════════════════════════════
    connect(ai_stop_btn_, &QPushButton::clicked, this, [this] {
        if (ai_assistant_) {
            ++ai_gen_id_;                          // invalidate all pending callbacks
            ai_assistant_->Abort();
            // Also cancel any engine scan a tool call (e.g. scan_directory) may
            // have kicked off -- without this, Stop only silenced the LLM's
            // token stream while a detached background scan thread kept
            // running unbounded, which is what made the chat page look
            // permanently "frozen" even after clicking Stop.
            if (engine_) engine_->CancelScan();
            if (ai_thinking_timer_) ai_thinking_timer_->stop();
            if (ai_typing_label_) {
                if (!ai_typing_text_.isEmpty())
                    ai_typing_label_->setText(ai_typing_text_);
                else
                    ai_typing_label_->setText(QString::fromUtf8("(D\xe1\xbb\xabng)"));
            }
            ai_typing_label_ = nullptr;
            ai_sending_ = false;
            ai_tool_loop_count_ = 0;
            ai_send_btn_->setEnabled(true);
            ai_input_edit_->setEnabled(true);
            ai_input_edit_->setFocus();
            ai_stop_btn_->setVisible(false);
            static_cast<AiAvatarWidget*>(ai_avatar_widget_)
                ->setState(AiAvatarWidget::State::Idle);
        }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // WIRE: Clear chat
    // ═══════════════════════════════════════════════════════════════════════════
    connect(clear_btn, &QPushButton::clicked, this, [this, kSystemPrompt] {
        while (ai_chat_layout_->count() > 0) {
            auto* item = ai_chat_layout_->takeAt(0);
            if (item->widget()) item->widget()->deleteLater();
            delete item;
        }
        ai_chat_layout_->addStretch();
        ai_typing_label_ = nullptr;
        ai_typing_text_.clear();
        ai_tool_loop_count_ = 0;
        ai_history_.clear();
        if (ai_assistant_) ai_history_.push_back({"system", kSystemPrompt});
    });

    // WIRE: New conversation (sidebar)
    connect(new_conv_btn, &QPushButton::clicked, clear_btn, &QPushButton::click);

    // WIRE: Sidebar tool buttons — each performs a real action, working even
    // when the AI model has not been loaded yet.
    connect(tool_analyze, &QPushButton::clicked, this, doAnalyzeFile);   // pick file → engine scan → History
    connect(tool_logs,    &QPushButton::clicked, this, [this] { GoToPage(5); }); // ETW Monitor
    connect(tool_yara,    &QPushButton::clicked, this,
            [aiPrefill] { aiPrefill(QString::fromUtf8("Please help me create a YARA rule to detect: ")); });
    connect(tool_reports, &QPushButton::clicked, this, doThreatReport);  // report from recent detections

    // ═══════════════════════════════════════════════════════════════════════════
    // WIRE: Inject detections
    // ═══════════════════════════════════════════════════════════════════════════
    connect(inject_btn, &QPushButton::clicked, this, [this] {
        const auto recent = engine_->RecentDetections(5);
        if (recent.empty()) {
            ai_input_edit_->setText(
                QString::fromUtf8("Ch\xc6\xb0" "a c\xc3\xb3 ph\xc3\xa1t hi\xe1\xbb\x87n n\xc3\xa0o."));
            return;
        }
        std::string ctx =
            "C\xc3\xa1" "c ph\xc3\xa1t hi\xe1\xbb\x87n g\xe1\xba\xa7n nh\xe1\xba\xa5t:\n";
        for (const auto& ev : recent) {
            ctx += "\xe2\x80\xa2 " + ev.rule_id + " [" +
                   (ev.severity == avcore::Severity::Malicious ? "MALICIOUS" :
                    ev.severity == avcore::Severity::Suspicious ? "SUSPICIOUS" : "INFO") +
                   "] " + ev.target_path + "\n  " + ev.evidence + "\n";
        }
        ctx += "\nPh\xc3\xa2n t\xc3\xad"
               "ch v\xc3\xa0 \xc4\x91\xe1\xbb\x81 xu\xe1\xba\xa5t bi\xe1\xbb\x87n ph\xc3\xa1p?";
        ai_input_edit_->setText(QString::fromUtf8(ctx.c_str()));
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // Model loads only when user clicks Load — do not auto-load on startup

    return page;
}

} // namespace avdashboard
