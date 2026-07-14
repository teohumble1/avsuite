#include "main_window.hpp"
#include "perf_mode.hpp"
#include "theme.hpp"

// Windows headers must come before Qt on Windows to avoid type conflicts.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>   // PROCESS_BASIC_INFORMATION, PEB, RTL_USER_PROCESS_PARAMETERS
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <atomic>
#include <thread>
#include <vector>

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QScreen>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QDateTime>
#include <QFileDialog>
#include <QFont>
#include <QFrame>
#include <QGroupBox>
#include <QEasingCurve>
#include <QGraphicsDropShadowEffect>
#include <QGraphicsOpacityEffect>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QProgressBar>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QScrollBar>
#include <QSizePolicy>
#include <QSpinBox>
#include <QStackedWidget>
#include <QStyle>
#include <QSystemTrayIcon>
#include <QTabWidget>
#include <QProcess>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariantAnimation>
#include <QWidget>

#include "avai/llm_assistant.hpp"
#include "avbehavior/process_event.hpp"
#include "avcore/severity.hpp"
#include "avengine/engine.hpp"
#include "av_animations.hpp"

namespace avdashboard {
    QWidget* BuildHistoryPage(QWidget* parent);
    QWidget* BuildInvestigationPage(QWidget* parent);
}

namespace avdashboard {

// ─── IconWidget ───────────────────────────────────────────────────────────────
// Lucide-style stroke icons drawn with QPainter. No SVG/font dependency.
class IconWidget : public QWidget {
public:
    enum Type {
        Home, AlertTriangle, Search, Archive, Settings, Lock, Activity, Ai,
        Shield, ShieldCheck, Zap, Folder, File, Database, Cpu, Link,
        TrendingUp, BarChart2, Bell, Globe, Wifi, Eye,
        Clock, HardDrive, List, ChevronRight, RefreshCw, UserCheck, Layers
    };

    explicit IconWidget(Type t, int sz, QColor c, QWidget* parent = nullptr)
        : QWidget(parent), type_(t), color_(c) {
        const int s = sz + 4;
        setFixedSize(s, s);
    }
    void setColor(const QColor& c) { color_ = c; update(); }
    void setType(Type t) { type_ = t; update(); }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const double m = 2.5;
        const double W = width() - m * 2, H = height() - m * 2;
        // Scale from 24x24 viewbox
        const double sx = W / 24.0, sy = H / 24.0;
        auto sc = [&](double x, double y) -> QPointF { return {m + x * sx, m + y * sy}; };
        auto scr = [&](double x, double y, double w, double h) -> QRectF {
            return {m + x * sx, m + y * sy, w * sx, h * sy};
        };
        QPen pen(color_, 1.6, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
        p.setPen(pen);
        p.setBrush(Qt::NoBrush);

        switch (type_) {
        case Home: {
            // Roof polygon
            QPainterPath roof;
            roof.moveTo(sc(3,9)); roof.lineTo(sc(12,2)); roof.lineTo(sc(21,9));
            roof.lineTo(sc(21,21)); roof.cubicTo(sc(21,22),sc(20,23),sc(19,23));
            roof.lineTo(sc(5,23)); roof.cubicTo(sc(4,23),sc(3,22),sc(3,21)); roof.closeSubpath();
            p.drawPath(roof);
            // Door
            QPainterPath door;
            door.moveTo(sc(9,23)); door.lineTo(sc(9,13)); door.lineTo(sc(15,13)); door.lineTo(sc(15,23));
            p.drawPath(door);
            break;
        }
        case AlertTriangle: {
            QPainterPath tri;
            tri.moveTo(sc(10.3,3.9)); tri.lineTo(sc(1.8,18));
            tri.cubicTo(sc(1,19.3),sc(1.9,21),sc(3.5,21));
            tri.lineTo(sc(20.5,21)); tri.cubicTo(sc(22.1,21),sc(23,19.3),sc(22.2,18));
            tri.lineTo(sc(13.7,3.9)); tri.cubicTo(sc(12.9,2.6),sc(11.1,2.6),sc(10.3,3.9)); tri.closeSubpath();
            p.drawPath(tri);
            p.drawLine(sc(12,9), sc(12,13));
            p.drawPoint(sc(12,17));
            break;
        }
        case Search: {
            p.drawEllipse(scr(3,3,13,13));
            QPen p2 = pen; p2.setWidthF(1.8); p.setPen(p2);
            p.drawLine(sc(14.7,14.7), sc(21,21));
            break;
        }
        case Archive: {
            // Box body
            QPainterPath box;
            box.addRoundedRect(scr(2,7,20,15), 2*sx, 2*sy);
            p.drawPath(box);
            // Lid
            QPainterPath lid;
            lid.addRoundedRect(scr(1,3,22,5), 1.5*sx, 1.5*sy);
            p.drawPath(lid);
            // Down arrow
            p.drawLine(sc(12,11), sc(12,17));
            QPainterPath arrow; arrow.moveTo(sc(9,14)); arrow.lineTo(sc(12,17)); arrow.lineTo(sc(15,14));
            p.drawPath(arrow);
            break;
        }
        case Settings: {
            // Circle center
            p.drawEllipse(scr(9,9,6,6));
            // Gear teeth (8 lines sticking out)
            const double cx=12, cy=12, r1=9, r2=12;
            for (int i=0; i<8; ++i) {
                const double a = i * M_PI / 4.0;
                const double cos_a = std::cos(a), sin_a = std::sin(a);
                p.drawLine(sc(cx+r1*cos_a*0.75, cy+r1*sin_a*0.75),
                           sc(cx+r2*cos_a*0.75, cy+r2*sin_a*0.75));
            }
            break;
        }
        case Lock: {
            QPainterPath body;
            body.addRoundedRect(scr(3,11,18,11), 2*sx, 2*sy);
            p.drawPath(body);
            QPainterPath arc;
            arc.moveTo(sc(8,11)); arc.arcTo(scr(6,3,12,12), 180, -180); arc.lineTo(sc(16,11));
            p.drawPath(arc);
            p.drawEllipse(scr(10.5,14.5,3,3));
            break;
        }
        case Activity: {
            p.drawLine(sc(2,12), sc(6,12));
            QPainterPath wave;
            wave.moveTo(sc(6,12)); wave.lineTo(sc(9,4)); wave.lineTo(sc(12,20));
            wave.lineTo(sc(15,8)); wave.lineTo(sc(18,12)); wave.lineTo(sc(22,12));
            p.drawPath(wave);
            break;
        }
        case Ai: {
            // Simple CPU/chip look
            QPainterPath chip;
            chip.addRoundedRect(scr(7,7,10,10), 1.5*sx, 1.5*sy);
            p.drawPath(chip);
            // Pins left
            for (int i=0; i<3; ++i) p.drawLine(sc(2,9+i*2.5), sc(7,9+i*2.5));
            // Pins right
            for (int i=0; i<3; ++i) p.drawLine(sc(17,9+i*2.5), sc(22,9+i*2.5));
            // Pins top
            for (int i=0; i<3; ++i) p.drawLine(sc(9+i*2.5,2), sc(9+i*2.5,7));
            // Pins bottom
            for (int i=0; i<3; ++i) p.drawLine(sc(9+i*2.5,17), sc(9+i*2.5,22));
            p.drawEllipse(scr(10,10,4,4));
            break;
        }
        case Shield: {
            QPainterPath sh;
            sh.moveTo(sc(12,2)); sh.lineTo(sc(22,6)); sh.lineTo(sc(22,13));
            sh.cubicTo(sc(22,18),sc(17.5,21.5),sc(12,22));
            sh.cubicTo(sc(6.5,21.5),sc(2,18),sc(2,13));
            sh.lineTo(sc(2,6)); sh.closeSubpath();
            p.drawPath(sh);
            break;
        }
        case ShieldCheck: {
            QPainterPath sh;
            sh.moveTo(sc(12,2)); sh.lineTo(sc(22,6)); sh.lineTo(sc(22,13));
            sh.cubicTo(sc(22,18),sc(17.5,21.5),sc(12,22));
            sh.cubicTo(sc(6.5,21.5),sc(2,18),sc(2,13));
            sh.lineTo(sc(2,6)); sh.closeSubpath();
            p.drawPath(sh);
            QPainterPath ck; ck.moveTo(sc(8,12)); ck.lineTo(sc(11,15)); ck.lineTo(sc(16,9));
            p.drawPath(ck);
            break;
        }
        case Zap: {
            QPainterPath z;
            z.moveTo(sc(13,2)); z.lineTo(sc(3,14)); z.lineTo(sc(12,14));
            z.lineTo(sc(11,22)); z.lineTo(sc(21,10)); z.lineTo(sc(12,10)); z.closeSubpath();
            p.drawPath(z);
            break;
        }
        case Folder: {
            QPainterPath f;
            f.moveTo(sc(3,5)); f.cubicTo(sc(3,4),sc(4,3),sc(5,3));
            f.lineTo(sc(9,3)); f.lineTo(sc(11,5.5)); f.lineTo(sc(21,5.5));
            f.cubicTo(sc(22,5.5),sc(22,6.5),sc(22,6.5));
            f.lineTo(sc(22,19)); f.cubicTo(sc(22,20),sc(21,21),sc(20,21));
            f.lineTo(sc(4,21)); f.cubicTo(sc(3,21),sc(2,20),sc(2,19));
            f.lineTo(sc(2,6)); f.cubicTo(sc(2,5.5),sc(2.5,5),sc(3,5)); f.closeSubpath();
            p.drawPath(f);
            break;
        }
        case File: {
            QPainterPath f;
            f.moveTo(sc(13,2)); f.lineTo(sc(4,2));
            f.cubicTo(sc(3,2),sc(2,3),sc(2,4)); f.lineTo(sc(2,20));
            f.cubicTo(sc(2,21),sc(3,22),sc(4,22)); f.lineTo(sc(20,22));
            f.cubicTo(sc(21,22),sc(22,21),sc(22,20)); f.lineTo(sc(22,11));
            f.closeSubpath(); p.drawPath(f);
            QPainterPath corner;
            corner.moveTo(sc(13,2)); corner.lineTo(sc(13,9)); corner.lineTo(sc(22,9));
            p.drawPath(corner);
            break;
        }
        case Database: {
            p.drawEllipse(scr(2,4,20,4));
            p.drawLine(sc(2,6), sc(2,18)); p.drawLine(sc(22,6), sc(22,18));
            p.drawEllipse(scr(2,11,20,4));
            p.drawEllipse(scr(2,15,20,5));
            break;
        }
        case Cpu: {
            QPainterPath chip;
            chip.addRoundedRect(scr(6,6,12,12), 2*sx, 2*sy);
            p.drawPath(chip);
            p.drawRect(scr(9,9,6,6));
            for (int i=0; i<3; ++i) {
                p.drawLine(sc(9+i*1.5,2), sc(9+i*1.5,6));
                p.drawLine(sc(9+i*1.5,18), sc(9+i*1.5,22));
                p.drawLine(sc(2,9+i*1.5), sc(6,9+i*1.5));
                p.drawLine(sc(18,9+i*1.5), sc(22,9+i*1.5));
            }
            break;
        }
        case Link: {
            QPainterPath l1;
            l1.moveTo(sc(10,13)); l1.cubicTo(sc(10.6,13.8),sc(11.4,14.4),sc(12.3,14.8));
            l1.cubicTo(sc(13.2,15.2),sc(14.2,15.3),sc(15.1,15));
            l1.cubicTo(sc(16,14.7),sc(16.8,14.1),sc(17.4,13.3));
            l1.lineTo(sc(20,11)); l1.cubicTo(sc(21.4,9.6),sc(21.4,7.3),sc(20,5.9));
            l1.cubicTo(sc(18.6,4.5),sc(16.3,4.5),sc(14.9,5.9)); l1.lineTo(sc(13.5,7.3));
            p.drawPath(l1);
            QPainterPath l2;
            l2.moveTo(sc(14,11)); l2.cubicTo(sc(13.4,10.2),sc(12.6,9.6),sc(11.7,9.2));
            l2.cubicTo(sc(10.8,8.8),sc(9.8,8.7),sc(8.9,9));
            l2.cubicTo(sc(8,9.3),sc(7.2,9.9),sc(6.6,10.7));
            l2.lineTo(sc(4,13)); l2.cubicTo(sc(2.6,14.4),sc(2.6,16.7),sc(4,18.1));
            l2.cubicTo(sc(5.4,19.5),sc(7.7,19.5),sc(9.1,18.1)); l2.lineTo(sc(10.5,16.7));
            p.drawPath(l2);
            break;
        }
        case TrendingUp: {
            QPainterPath t;
            t.moveTo(sc(23,6)); t.lineTo(sc(17,6)); t.lineTo(sc(17,12));
            p.drawPath(t);
            QPainterPath line;
            line.moveTo(sc(23,6)); line.lineTo(sc(14,15)); line.lineTo(sc(9,10)); line.lineTo(sc(1,18));
            p.drawPath(line);
            break;
        }
        case BarChart2: {
            p.drawLine(sc(18,2), sc(18,22));
            p.drawLine(sc(12,6), sc(12,22));
            p.drawLine(sc(6,12), sc(6,22));
            p.drawLine(sc(2,22), sc(22,22));
            break;
        }
        case Bell: {
            QPainterPath bell;
            bell.moveTo(sc(12,1.5));
            bell.cubicTo(sc(7,1.5),sc(4,6),sc(4,11));
            bell.lineTo(sc(4,16)); bell.lineTo(sc(2,20)); bell.lineTo(sc(22,20));
            bell.lineTo(sc(20,16)); bell.lineTo(sc(20,11));
            bell.cubicTo(sc(20,6),sc(17,1.5),sc(12,1.5)); bell.closeSubpath();
            p.drawPath(bell);
            p.drawArc(scr(9,20,6,3), 180*16, -180*16);
            break;
        }
        case Globe: {
            p.drawEllipse(scr(2,2,20,20));
            // Longitude lines
            p.drawLine(sc(12,2), sc(12,22));
            // Latitude lines
            QPainterPath eq; eq.moveTo(sc(2,12));
            eq.cubicTo(sc(7,8),sc(17,8),sc(22,12));
            eq.cubicTo(sc(17,16),sc(7,16),sc(2,12));
            p.drawPath(eq);
            break;
        }
        case Wifi: {
            // 3 arcs
            for (int i=3; i>=1; --i) {
                const double sz_ = i * 5.0;
                const double cx = 12, top = 12 - sz_;
                QPainterPath arc;
                arc.moveTo(sc(cx - sz_, 12));
                arc.cubicTo(sc(cx-sz_,top+sz_*0.3),sc(cx-sz_*0.3,top),sc(cx,top));
                arc.cubicTo(sc(cx+sz_*0.3,top),sc(cx+sz_,top+sz_*0.3),sc(cx+sz_,12));
                p.drawPath(arc);
            }
            p.drawEllipse(scr(11,19,2,2));
            break;
        }
        case Eye: {
            QPainterPath eye;
            eye.moveTo(sc(1,12));
            eye.cubicTo(sc(5,5),sc(9,3),sc(12,3));
            eye.cubicTo(sc(15,3),sc(19,5),sc(23,12));
            eye.cubicTo(sc(19,19),sc(15,21),sc(12,21));
            eye.cubicTo(sc(9,21),sc(5,19),sc(1,12));
            p.drawPath(eye);
            p.drawEllipse(scr(9,9,6,6));
            break;
        }
        case Clock: {
            p.drawEllipse(scr(2,2,20,20));
            p.drawLine(sc(12,6), sc(12,12));
            p.drawLine(sc(12,12), sc(16,14));
            break;
        }
        case HardDrive: {
            QPainterPath hd;
            hd.addRoundedRect(scr(2,2,20,20), 3*sx, 3*sy);
            p.drawPath(hd);
            p.drawLine(sc(2,13), sc(22,13));
            p.drawEllipse(scr(14,16,3,3));
            break;
        }
        case List: {
            p.drawLine(sc(8,6), sc(21,6));
            p.drawLine(sc(8,12), sc(21,12));
            p.drawLine(sc(8,18), sc(21,18));
            p.drawEllipse(scr(3,5.5,2,2));
            p.drawEllipse(scr(3,11.5,2,2));
            p.drawEllipse(scr(3,17.5,2,2));
            break;
        }
        case ChevronRight: {
            QPainterPath ch;
            ch.moveTo(sc(9,6)); ch.lineTo(sc(15,12)); ch.lineTo(sc(9,18));
            p.drawPath(ch);
            break;
        }
        case RefreshCw: {
            // Arc going clockwise ~300 degrees
            QPainterPath arc;
            arc.moveTo(sc(1,4)); arc.lineTo(sc(1,9)); arc.lineTo(sc(6,9));
            p.drawPath(arc);
            QPainterPath arc2;
            arc2.moveTo(sc(1,9));
            arc2.cubicTo(sc(3,14),sc(7,19),sc(12,20));
            arc2.cubicTo(sc(17,21),sc(22,17),sc(23,12));
            arc2.cubicTo(sc(23,6),sc(17.5,2),sc(12,2));
            arc2.cubicTo(sc(8,2),sc(4.5,4),sc(2.5,7));
            p.drawPath(arc2);
            break;
        }
        case UserCheck: {
            QPainterPath head;
            head.addEllipse(scr(4,2,8,8));
            p.drawPath(head);
            QPainterPath body;
            body.moveTo(sc(2,21)); body.cubicTo(sc(2,17),sc(5,15),sc(8,15));
            body.cubicTo(sc(11,15),sc(14,17),sc(14,21));
            p.drawPath(body);
            QPainterPath check2;
            check2.moveTo(sc(16,11)); check2.lineTo(sc(18,13)); check2.lineTo(sc(22,9));
            p.drawPath(check2);
            break;
        }
        case Layers: {
            QPainterPath l;
            l.moveTo(sc(12,2)); l.lineTo(sc(2,7)); l.lineTo(sc(12,12)); l.lineTo(sc(22,7)); l.closeSubpath();
            p.drawPath(l);
            p.drawPolyline(QPolygonF({sc(2,12),sc(12,17),sc(22,12)}));
            p.drawPolyline(QPolygonF({sc(2,17),sc(12,22),sc(22,17)}));
            break;
        }
        }
    }

private:
    Type type_;
    QColor color_;
};

// ─── CyberTile ────────────────────────────────────────────────────────────────
// 3-D quick-action tile: gradient surface, shimmer sweep on hover, neon glow
// drop-shadow, and a pressed-down depth effect — fully custom paintEvent.
class CyberTile : public QPushButton {
public:
    explicit CyberTile(const QString& text, QWidget* parent = nullptr)
        : QPushButton(text, parent)
    {
        const bool low = IsLowEndSystem();

        // The neon glow drop-shadow is a CPU-rasterised QGraphicsEffect whose
        // blur is re-rendered every animation frame — the single most expensive
        // per-tile effect. Skip it entirely on low-end/old hardware.
        if (!low) {
            shadow_ = new QGraphicsDropShadowEffect(this);
            shadow_->setColor(QColor(255, 122, 0, 0));
            shadow_->setBlurRadius(0);
            shadow_->setOffset(0, 4);
            setGraphicsEffect(shadow_);
        }

        // Shimmer sweep (runs only while hovered). 60fps on capable machines,
        // a lighter ~25fps on low-end so it never pegs a weak CPU/iGPU.
        shimmer_timer_ = new QTimer(this);
        shimmer_timer_->setInterval(low ? 40 : 16);
        connect(shimmer_timer_, &QTimer::timeout, this, [this] {
            shimmer_x_ += 3.5;
            if (shimmer_x_ > width() + 70.0) shimmer_x_ = -70.0;
            update();
        });

        // Smooth glow in/out — it only drives the drop shadow, so it's pointless
        // (and its valueChanged would deref a null shadow_) on low-end. Skip it.
        if (!low) {
            glow_anim_ = new QVariantAnimation(this);
            glow_anim_->setDuration(180);
            glow_anim_->setEasingCurve(QEasingCurve::InOutQuad);
            glow_anim_->setStartValue(0.0);
            glow_anim_->setEndValue(1.0);
            connect(glow_anim_, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
                glow_t_ = v.toDouble();
                shadow_->setBlurRadius(glow_t_ * 28.0);
                shadow_->setColor(QColor(255, 122, 0, static_cast<int>(glow_t_ * 160)));
                update();
            });
        }
    }

protected:
    void enterEvent(QEnterEvent* e) override {
        QPushButton::enterEvent(e);
        if (glow_anim_) {
            glow_anim_->setDirection(QAbstractAnimation::Forward);
            glow_anim_->start();
        }
        shimmer_x_ = -70.0;
        shimmer_timer_->start();
    }
    void leaveEvent(QEvent* e) override {
        QPushButton::leaveEvent(e);
        if (glow_anim_) {
            glow_anim_->setDirection(QAbstractAnimation::Backward);
            glow_anim_->start();
        }
        shimmer_timer_->stop();
        shimmer_x_ = -200.0;
        update();
    }

    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);

        const bool pressed = isDown();
        const double g = glow_t_;
        const QRectF r(1.5, 1.5, width() - 3.0, height() - 3.0);
        constexpr int kR = 12;

        QPainterPath path;
        path.addRoundedRect(r, kR, kR);

        // ── 3D Base gradient (lit from top-left) ──────────────────────────
        QLinearGradient base(r.left(), r.top(), r.left(), r.bottom());
        if (pressed) {
            base.setColorAt(0,    QColor(60,  20,  0));
            base.setColorAt(1,    QColor(90,  35,  0));
        } else {
            const int b = static_cast<int>(g * 24);
            base.setColorAt(0,    QColor(210+b, 90,  0));
            base.setColorAt(0.42, QColor(180+b, 72,  0));
            base.setColorAt(0.52, QColor(152,   58,  0));
            base.setColorAt(1,    QColor(110,   40,  0));
        }
        p.fillPath(path, base);

        // ── Inner top-edge highlight (3D reflection) ──────────────────────
        if (!pressed) {
            const int ha = static_cast<int>(32 + g * 36);
            QLinearGradient hl(r.left(), r.top(), r.left(), r.top() + r.height() * 0.38);
            hl.setColorAt(0, QColor(255, 255, 255, ha));
            hl.setColorAt(1, QColor(255, 255, 255,  0));
            p.fillPath(path, hl);
        }

        // ── Diagonal shimmer sweep ────────────────────────────────────────
        if (shimmer_x_ > -60.0 && !pressed) {
            constexpr double sw = 62.0;
            QLinearGradient sh(shimmer_x_ - sw, r.top(),
                               shimmer_x_ + sw, r.bottom());
            sh.setColorAt(0,    QColor(255,255,255, 0));
            sh.setColorAt(0.38, QColor(255,255,255, 0));
            sh.setColorAt(0.5,  QColor(255,255,255,38));
            sh.setColorAt(0.62, QColor(255,255,255, 0));
            sh.setColorAt(1,    QColor(255,255,255, 0));
            p.fillPath(path, sh);
        }

        // ── Border: neon on hover, dim at rest ────────────────────────────
        const int ba = static_cast<int>(g * 110 + 70);
        p.setPen(QPen(pressed
            ? QColor(80, 28, 0, 90)
            : QColor(255, static_cast<int>(g*90+80), 0, ba), 1.0));
        p.drawPath(path);

        // ── Bottom 3D shadow edge ─────────────────────────────────────────
        if (!pressed) {
            QPainterPath bot;
            bot.addRoundedRect(
                QRectF(r.left()+3, r.bottom()-3.5, r.width()-6, 3.5), 4, 4);
            p.fillPath(bot, QColor(30, 10, 0, static_cast<int>(100 + g*60)));
        }

        // ── Text ──────────────────────────────────────────────────────────
        p.setPen(pressed ? QColor(230,190,140) : QColor(255,230,200));
        QFont f = font();
        f.setWeight(QFont::Bold);
        p.setFont(f);
        const int oy = pressed ? 1 : 0;
        p.drawText(r.adjusted(0,oy,0,oy).toRect(),
                   Qt::AlignCenter | Qt::TextWordWrap, text());
    }

private:
    QGraphicsDropShadowEffect* shadow_        = nullptr;
    QVariantAnimation*         glow_anim_     = nullptr;
    QTimer*                    shimmer_timer_  = nullptr;
    double                     shimmer_x_      = -200.0;
    double                     glow_t_         = 0.0;
};

// ─── PulseStatusCircle ────────────────────────────────────────────────────────
// 3D sphere + 5 expanding neon pulse rings + icon (shield or threat "!").
// Entire rendering is done in paintEvent — no stylesheet backgrounds.
class PulseStatusCircle : public QFrame {
public:
    explicit PulseStatusCircle(QWidget* parent = nullptr) : QFrame(parent) {
        auto* timer = new QTimer(this);
        connect(timer, &QTimer::timeout, this, [this] {
            phase_ = std::fmod(phase_ + 0.014f, 1.0f);
            update();
        });
        timer->start(30);
    }

    void setActiveColor(const QColor& c) { color_ = c; update(); }
    void setState(bool threat) { threat_ = threat; update(); }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);

        const double cx = width()  / 2.0;
        const double cy = height() / 2.0;
        const double base_r = std::min(width(), height()) / 2.0 - 6.0;

        // ── Outer atmosphere glow ─────────────────────────────────────────
        {
            QRadialGradient atm(cx, cy, base_r * 2.2);
            QColor ac = color_; ac.setAlpha(threat_ ? 30 : 18);
            atm.setColorAt(0,   ac);
            ac.setAlpha(0); atm.setColorAt(1, ac);
            p.setPen(Qt::NoPen);
            p.setBrush(atm);
            p.drawEllipse(QPointF(cx, cy), base_r * 2.2, base_r * 2.2);
        }

        // ── 5 expanding pulse rings ───────────────────────────────────────
        p.setBrush(Qt::NoBrush);
        for (int i = 0; i < 5; ++i) {
            const double t    = std::fmod(phase_ + i / 5.0, 1.0);
            const double ring_r = base_r + t * 44.0;
            const double fade = 1.0 - t;
            const int    alpha = static_cast<int>(fade * fade * (threat_ ? 80.0 : 55.0));
            if (alpha < 2) continue;
            const double width_px = 1.0 + (1.0 - t) * 1.5;
            QColor rc = color_; rc.setAlpha(alpha);
            p.setPen(QPen(rc, width_px));
            p.drawEllipse(QPointF(cx, cy), ring_r, ring_r);
        }
        p.setPen(Qt::NoPen);

        // ── Warp helper: 3-wave sinusoidal path, used only inside the sphere rim
        const double warpAmp = threat_ ? 2.2 : 0.9;
        auto warpedInner = [&](double r) -> QPainterPath {
            QPainterPath path;
            constexpr int steps = 128;
            for (int j = 0; j <= steps; ++j) {
                const double theta = 2.0 * M_PI * j / steps;
                const double pr = r + warpAmp * std::sin(3.0 * theta + phase_ * 2.0 * M_PI);
                const QPointF pt(cx + pr * std::cos(theta), cy + pr * std::sin(theta));
                if (j == 0) path.moveTo(pt); else path.lineTo(pt);
            }
            path.closeSubpath();
            return path;
        };

        // ── 3D Sphere base ────────────────────────────────────────────────
        // Dark outer rim — kept as clean ellipse so no gaps appear at boundary
        {
            QRadialGradient rim(cx, cy, base_r);
            QColor dark = color_.darker(200); dark.setAlpha(160);
            QColor mid  = color_.darker(120); mid.setAlpha(80);
            rim.setColorAt(0.75, mid);
            rim.setColorAt(1,    dark);
            p.setBrush(rim); p.drawEllipse(QPointF(cx, cy), base_r, base_r);
        }
        // Sphere fill (lit from top-left) — warped interior
        {
            const double lx = cx - base_r * 0.28, ly = cy - base_r * 0.28;
            QRadialGradient sphere(lx, ly, base_r * 1.6, cx, cy);
            QColor bright = color_.lighter(threat_ ? 130 : 160); bright.setAlpha(210);
            QColor mid    = color_;                               mid.setAlpha(180);
            QColor dark   = color_.darker(160);                   dark.setAlpha(200);
            sphere.setColorAt(0.0,  bright);
            sphere.setColorAt(0.45, mid);
            sphere.setColorAt(1.0,  dark);
            p.setBrush(sphere);
            p.drawPath(warpedInner(base_r - 2));
        }
        // ── Opacity veil (dims sphere surface, stronger on threat) ────────
        {
            p.setBrush(QColor(0, 0, 0, threat_ ? 58 : 18));
            p.setPen(Qt::NoPen);
            p.drawPath(warpedInner(base_r - 2));
        }
        // Specular highlight (top-left white glint)
        {
            const double hx = cx - base_r * 0.32, hy = cy - base_r * 0.30;
            QRadialGradient spec(hx, hy, base_r * 0.55);
            spec.setColorAt(0.0, QColor(255, 255, 255, threat_ ? 60 : 80));
            spec.setColorAt(1.0, QColor(255, 255, 255,  0));
            p.setBrush(spec);
            p.drawPath(warpedInner(base_r - 2));
        }
        // Inner border ring
        {
            QColor border = color_.lighter(140); border.setAlpha(180);
            p.setPen(QPen(border, 2.5));
            p.setBrush(Qt::NoBrush);
            p.drawPath(warpedInner(base_r - 2));
            p.setPen(Qt::NoPen);
        }

        // ── Icon ──────────────────────────────────────────────────────────
        if (threat_) {
            // Pulsing "!" exclamation
            const double flash = 0.58 + 0.42 * std::sin(static_cast<double>(phase_) * 2.0 * M_PI * 2.8);
            QColor ic(255, 80, 100, static_cast<int>(240.0 * flash));
            p.setBrush(ic);

            constexpr double bar_w = 10.0, bar_h = 26.0, gap = 6.0, dot_r = 6.0;
            constexpr double total_h = bar_h + gap + dot_r * 2.0;
            const double sy = cy - total_h / 2.0;

            p.drawRoundedRect(QRectF(cx - bar_w/2.0, sy, bar_w, bar_h),
                              bar_w/2.0, bar_w/2.0);
            p.drawEllipse(QPointF(cx, sy + bar_h + gap + dot_r), dot_r, dot_r);
        } else {
            // Shield icon with gradient fill
            constexpr double sw = 46.0, sh = 52.0;
            const double sx = cx - sw/2.0, sy = cy - sh/2.0;

            QPainterPath shield;
            shield.moveTo(cx, sy);
            shield.lineTo(sx + sw, sy + sh * 0.18);
            shield.lineTo(sx + sw, sy + sh * 0.56);
            shield.cubicTo(sx+sw,  sy+sh*0.82, cx+sw*0.25, sy+sh*0.96, cx, sy+sh);
            shield.cubicTo(cx-sw*0.25, sy+sh*0.96, sx, sy+sh*0.82, sx, sy+sh*0.56);
            shield.lineTo(sx, sy + sh * 0.18);
            shield.closeSubpath();

            // Gradient shield fill
            QLinearGradient sfill(sx, sy, sx+sw, sy+sh);
            sfill.setColorAt(0, QColor(color_.red(), color_.green(), color_.blue(), 120));
            sfill.setColorAt(1, QColor(color_.red(), color_.green(), color_.blue(),  50));
            p.setBrush(sfill);
            p.setPen(Qt::NoPen);
            p.fillPath(shield, sfill);

            QColor outline = color_; outline.setAlpha(220);
            p.setPen(QPen(outline, 2.5));
            p.setBrush(Qt::NoBrush);
            p.drawPath(shield);

            // Checkmark
            p.setPen(QPen(outline, 3.2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            QPainterPath ck;
            ck.moveTo(cx - 10, cy + sh*0.04);
            ck.lineTo(cx -  2, cy + sh*0.04 + 8.5);
            ck.lineTo(cx + 12, cy + sh*0.04 - 9);
            p.drawPath(ck);
        }
    }

private:
    float  phase_  = 0.0f;
    bool   threat_ = false;
    QColor color_  {74, 222, 128};
};

// ─── BadgeButton ─────────────────────────────────────────────────────────────
// Nav button subclass that draws a small red circle badge (count > 0) at its
// top-right corner. Used for the History nav entry to show unread detections.
class BadgeButton : public QPushButton {
public:
    explicit BadgeButton(const QString& text, QWidget* parent = nullptr)
        : QPushButton(text, parent) {}

    void setBadge(int n) {
        if (badge_ == n) return;
        badge_ = n;
        update();
    }

protected:
    void paintEvent(QPaintEvent* e) override {
        QPushButton::paintEvent(e);
        if (badge_ <= 0) return;

        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);

        const QString text = badge_ > 99 ? QString("99+") : QString::number(badge_);
        const QFont font("Segoe UI", 7, QFont::Bold);
        p.setFont(font);
        const QFontMetrics fm(font);
        const int tw = fm.horizontalAdvance(text);

        const int r = 9;
        const int diameter = std::max(2 * r, tw + 8);
        const int bx = width() - diameter - 6;
        const int by = 5;

        p.setPen(Qt::NoPen);
        p.setBrush(QColor(0xeb, 0x3b, 0x5a));
        p.drawRoundedRect(bx, by, diameter, 2 * r, r, r);

        p.setPen(Qt::white);
        p.drawText(QRect(bx, by, diameter, 2 * r), Qt::AlignCenter, text);
    }

private:
    int badge_ = 0;
};

// ─── DetectionBarChart ────────────────────────────────────────────────────────
// Custom QWidget that draws a stacked bar chart of detections for the last
// 7 days (info=gray, suspicious=yellow, malicious=red). No Q_OBJECT needed
// since there are no signals/slots -- just setData() + paintEvent().
class DetectionBarChart : public QWidget {
public:
    explicit DetectionBarChart(QWidget* parent = nullptr) : QWidget(parent) {
        setMinimumHeight(150);
        setMaximumHeight(190);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

    void setData(const std::vector<avcore::DetectionEvent>& events) {
        std::array<Bucket, 7> buckets{};
        labels_.clear();

        const auto now = std::chrono::system_clock::now();
        for (int d = 6; d >= 0; --d) {
            const auto tp = now - std::chrono::hours(24 * d);
            const auto t = std::chrono::system_clock::to_time_t(tp);
            std::tm tm{};
            localtime_s(&tm, &t);
            char buf[8];
            strftime(buf, sizeof(buf), "%d/%m", &tm);
            labels_.push_back(d == 0 ? QString::fromUtf8("Hôm nay") : QString::fromLatin1(buf));
        }

        for (const auto& ev : events) {
            const auto age_h = std::chrono::duration_cast<std::chrono::hours>(
                now - ev.timestamp).count();
            if (age_h < 0 || age_h >= 7 * 24) continue;
            const int idx = 6 - static_cast<int>(age_h / 24);
            if (idx < 0 || idx >= 7) continue;
            switch (ev.severity) {
                case avcore::Severity::Malicious:  ++buckets[static_cast<std::size_t>(idx)].malicious; break;
                case avcore::Severity::Suspicious: ++buckets[static_cast<std::size_t>(idx)].suspicious; break;
                default:                           ++buckets[static_cast<std::size_t>(idx)].info; break;
            }
        }
        data_.clear();
        for (const auto& b : buckets) data_.push_back(b);
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);

        const int W = width(), H = height();
        const int ml = 32, mr = 8, mt = 20, mb = 38;
        const int cw = W - ml - mr, ch = H - mt - mb;

        int max_val = 1;
        for (const auto& d : data_)
            max_val = std::max(max_val, d.malicious + d.suspicious + d.info);

        const int n = static_cast<int>(data_.size());
        const int slot = (n > 0) ? cw / n : cw;
        const int bw   = std::max(8, slot * 58 / 100);

        // ── Grid lines ────────────────────────────────────────────────────
        for (int g = 0; g <= 4; ++g) {
            const int gy = mt + ch * g / 4;
            p.setPen(QPen(QColor(255,122,0, g == 4 ? 22 : 10), 1,
                          g == 4 ? Qt::SolidLine : Qt::DashLine));
            p.drawLine(ml, gy, ml + cw, gy);

            // Y-axis value label
            if (g < 4) {
                const int val = max_val * (4 - g) / 4;
                QFont gf; gf.setPointSize(6); p.setFont(gf);
                p.setPen(QColor(180, 120, 60, 80));
                p.drawText(QRect(0, gy - 8, ml - 4, 16),
                           Qt::AlignRight | Qt::AlignVCenter,
                           QString::number(val));
            }
        }

        // ── Bars ──────────────────────────────────────────────────────────
        for (int i = 0; i < n; ++i) {
            const auto& d   = data_[static_cast<std::size_t>(i)];
            const int total = d.malicious + d.suspicious + d.info;
            const int x     = ml + i * slot + (slot - bw) / 2;
            int y           = mt + ch;

            // Draw one gradient segment (bottom-to-top stacking)
            auto drawGradSeg = [&](int count,
                                   const QColor& top_c, const QColor& bot_c,
                                   bool is_top_of_stack)
            {
                if (count <= 0) return;
                const int h = std::max(3, (count * ch) / max_val);
                y -= h;

                QLinearGradient g(x, y, x, y + h);
                g.setColorAt(0.0, top_c);
                g.setColorAt(1.0, bot_c);

                QPainterPath bp;
                if (is_top_of_stack)
                    bp.addRoundedRect(x, y, bw, h, 4, 4);
                else
                    bp.addRect(x, y, bw, h);
                p.setPen(Qt::NoPen);
                p.fillPath(bp, g);

                // Thin highlight on top edge (3D depth)
                p.setPen(QPen(QColor(255,255,255,28), 1));
                p.drawLine(x, y, x + bw, y);
                p.setPen(Qt::NoPen);
            };

            // Stack order: info (bottom) → suspicious → malicious (top)
            const bool has_susp = d.suspicious > 0;
            const bool has_mal  = d.malicious  > 0;
            drawGradSeg(d.info,
                QColor(40, 180, 255, 145), QColor(7, 90, 200, 70),
                (!has_susp && !has_mal));
            drawGradSeg(d.suspicious,
                QColor(255, 215, 55, 210), QColor(200, 135, 15, 130),
                !has_mal);
            drawGradSeg(d.malicious,
                QColor(255, 75, 105, 225), QColor(180, 25, 55, 145),
                true);

            // Luminous cap on top
            if (total > 0) {
                const QColor cap_c = d.malicious > 0 ? QColor(255,90,115,180)
                                   : d.suspicious > 0 ? QColor(255,225,70,160)
                                   : QColor(60,200,255,130);
                QLinearGradient cap(x, y, x+bw, y);
                cap.setColorAt(0, cap_c.lighter(145));
                cap.setColorAt(1, cap_c);
                QPainterPath cp;
                cp.addRoundedRect(x, y, bw, 3, 2, 2);
                p.fillPath(cp, cap);
            }

            // Day label
            QFont lf; lf.setPointSize(7); p.setFont(lf);
            p.setPen(QColor(180, 140, 90, 155));
            const QString lbl = (i < static_cast<int>(labels_.size()))
                ? labels_[static_cast<std::size_t>(i)] : "";
            p.drawText(QRect(x-(slot-bw)/2, mt+ch+6, slot, mb-8),
                       Qt::AlignCenter, lbl);

            // Count badge above tallest bar
            if (total > 0) {
                QFont vf; vf.setPointSize(7); vf.setBold(true); p.setFont(vf);
                p.setPen(QColor(230, 200, 160, 210));
                p.drawText(QRect(x-4, y-16, bw+8, 14),
                           Qt::AlignCenter, QString::number(total));
            }
        }

        // ── Legend ────────────────────────────────────────────────────────
        auto drawLegendPill = [&](int lx, const QColor& c, const QString& label) {
            QLinearGradient g(lx, 4, lx+10, 14);
            g.setColorAt(0, c.lighter(160));
            g.setColorAt(1, c);
            QPainterPath lp;
            lp.addRoundedRect(lx, 4, 10, 10, 3, 3);
            p.setPen(Qt::NoPen);
            p.fillPath(lp, g);
            QFont lf; lf.setPointSize(7); p.setFont(lf);
            p.setPen(QColor(180, 150, 100, 165));
            p.drawText(lx + 13, 14, label);
        };
        drawLegendPill(ml,       QColor(235, 59, 90),  "Malicious");
        drawLegendPill(ml + 76,  QColor(247, 183, 49), "Suspicious");
        drawLegendPill(ml + 166, QColor(40, 180, 255), "Info");
    }

private:
    struct Bucket { int malicious = 0, suspicious = 0, info = 0; };
    std::vector<Bucket> data_;
    std::vector<QString> labels_;
};

// ─── MiniAreaChart ────────────────────────────────────────────────────────────
// Lightweight animated area chart for the right-panel cards.
class MiniAreaChart : public QWidget {
public:
    explicit MiniAreaChart(const QColor& c, int h, QWidget* parent = nullptr)
        : QWidget(parent), color_(c) {
        setFixedHeight(h);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        for (int i = 0; i < 14; ++i) {
            const double v = 8.0 + 7.0 * std::sin(i * 0.55) + 4.0 * std::cos(i * 0.92);
            data_.push_back(std::max(1.0, v));
        }
    }

    void tick() {
        tick_ = (tick_ + 1) % 628;
        data_.erase(data_.begin());
        const double v = 10.0 + 7.0 * std::sin(tick_ * 0.12)
                              + 4.0 * std::cos(tick_ * 0.31)
                              + 2.0 * std::sin(tick_ * 0.57 + 1.2);
        data_.push_back(std::max(1.0, v));
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const int W = width(), H = height();
        const int n = static_cast<int>(data_.size());
        if (n < 2) return;

        double max_v = *std::max_element(data_.begin(), data_.end());
        if (max_v < 1.0) max_v = 1.0;

        QPainterPath line;
        for (int i = 0; i < n; ++i) {
            const double x = W * i / (n - 1.0);
            const double y = H - (data_[static_cast<std::size_t>(i)] / max_v) * (H - 4) - 2;
            if (i == 0) line.moveTo(x, y); else line.lineTo(x, y);
        }
        QPainterPath fill = line;
        fill.lineTo(W, H); fill.lineTo(0, H); fill.closeSubpath();

        QLinearGradient g(0, 0, 0, H);
        QColor c1 = color_; c1.setAlpha(55);
        QColor c2 = color_; c2.setAlpha(0);
        g.setColorAt(0, c1); g.setColorAt(1, c2);
        p.setPen(Qt::NoPen);
        p.fillPath(fill, g);

        p.setPen(QPen(color_, 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.setBrush(Qt::NoBrush);
        p.drawPath(line);
    }

private:
    QColor color_;
    std::vector<double> data_;
    int tick_ = 0;
};

// ─── ToggleSwitch ─────────────────────────────────────────────────────────────
// Orange toggle switch for Protection Layers.
class ToggleSwitch : public QPushButton {
public:
    explicit ToggleSwitch(QWidget* parent = nullptr) : QPushButton(parent) {
        setCheckable(true);
        setFixedSize(36, 20);
        setCursor(Qt::PointingHandCursor);
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);

        const bool on = isChecked();
        QPainterPath track;
        track.addRoundedRect(QRectF(0, 0, 36, 20), 10, 10);
        p.setPen(Qt::NoPen);
        p.fillPath(track, on ? QColor(255, 122, 0) : QColor(58, 37, 24));
        p.setBrush(Qt::white);
        p.drawEllipse(QRectF(on ? 18.0 : 2.0, 2.0, 16, 16));
    }
};

// ─── ScoreRingWidget ──────────────────────────────────────────────────────────
// Circular progress arc showing the security score (0-100).
class ScoreRingWidget : public QWidget {
public:
    explicit ScoreRingWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedSize(64, 64);
    }
    void setScore(int score) { score_ = score; update(); }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const QRectF r(5, 5, 54, 54);
        constexpr int arc_w = 5;

        p.setPen(QPen(QColor(255, 170, 90, 26), arc_w));
        p.setBrush(Qt::NoBrush);
        p.drawEllipse(r);

        const int span = static_cast<int>(360.0 * score_ / 100.0 * 16);
        p.setPen(QPen(QColor(255, 122, 0), arc_w, Qt::SolidLine, Qt::RoundCap));
        p.drawArc(r, 90 * 16, -span);

        QFont f; f.setPointSize(11); f.setWeight(QFont::DemiBold);
        p.setFont(f);
        p.setPen(Qt::white);
        p.drawText(r.toRect(), Qt::AlignCenter, QString::number(score_));
    }

private:
    int score_ = 97;
};

// ─── ShieldIconWidget ─────────────────────────────────────────────────────────
// Flat shield icon in orange gradient box + green/red badge at bottom-right.
// Matches the Figma shield card icon exactly.
class ShieldIconWidget : public QWidget {
public:
    explicit ShieldIconWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedSize(68, 68);
    }
    void setThreat(bool threat) {
        if (threat_ == threat) return;
        threat_ = threat;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);

        // Box: orange gradient rounded rect
        QPainterPath box;
        box.addRoundedRect(QRectF(2, 2, 60, 60), 14, 14);
        QLinearGradient bg(2, 2, 62, 62);
        bg.setColorAt(0, QColor(255, 122, 0, 51));
        bg.setColorAt(1, QColor(255, 85, 0, 26));
        p.fillPath(box, bg);
        p.setPen(QPen(QColor(255, 122, 0, 64), 1.0));
        p.drawPath(box);
        p.setPen(Qt::NoPen);

        // Shield outline
        const double cx = 32, cy = 30;
        const double sw = 28, sh = 32;
        const double sx = cx - sw / 2, sy = cy - sh / 2;
        QPainterPath shield;
        shield.moveTo(cx, sy);
        shield.lineTo(sx + sw, sy + sh * 0.18);
        shield.lineTo(sx + sw, sy + sh * 0.56);
        shield.cubicTo(sx + sw, sy + sh * 0.82, cx + sw * 0.25, sy + sh * 0.96, cx, sy + sh);
        shield.cubicTo(cx - sw * 0.25, sy + sh * 0.96, sx, sy + sh * 0.82, sx, sy + sh * 0.56);
        shield.lineTo(sx, sy + sh * 0.18);
        shield.closeSubpath();

        const QColor icon_col = threat_ ? QColor(255, 90, 106) : QColor(255, 122, 0);
        p.setPen(QPen(icon_col, 2.2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.drawPath(shield);

        // Checkmark or X
        if (!threat_) {
            QPainterPath ck;
            ck.moveTo(cx - 7, cy + 2);
            ck.lineTo(cx - 1, cy + 8);
            ck.lineTo(cx + 9, cy - 5);
            p.drawPath(ck);
        } else {
            p.drawLine(QPointF(cx - 6, cy - 5), QPointF(cx + 6, cy + 5));
            p.drawLine(QPointF(cx + 6, cy - 5), QPointF(cx - 6, cy + 5));
        }
        p.setPen(Qt::NoPen);

        // Badge circle at bottom-right
        const QColor badge_col = threat_ ? QColor(255, 90, 106) : QColor(74, 222, 128);
        p.setBrush(badge_col);
        p.drawEllipse(QRectF(46, 46, 20, 20));

        // White symbol in badge
        p.setPen(QPen(Qt::white, 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        if (!threat_) {
            QPainterPath bck;
            bck.moveTo(49, 56); bck.lineTo(53, 60); bck.lineTo(60, 51);
            p.drawPath(bck);
        } else {
            p.drawLine(QPointF(50, 50), QPointF(62, 62));
            p.drawLine(QPointF(62, 50), QPointF(50, 62));
        }
        p.setPen(Qt::NoPen);
    }

private:
    bool threat_ = false;
};

// ─── MiniLineChart ────────────────────────────────────────────────────────────
// Security Score line chart for the right panel — shows 12 oscillating score
// values (88-100 range), self-animating via QTimer.
class MiniLineChart : public QWidget {
public:
    explicit MiniLineChart(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedHeight(72);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        for (int i = 0; i < 12; ++i) {
            const double v = 96.0 + 3.0 * std::sin(i * 0.55) + 1.5 * std::cos(i * 1.0);
            data_.push_back(std::clamp(v, 88.0, 100.0));
        }
        auto* timer = new QTimer(this);
        timer->setInterval(2800);
        connect(timer, &QTimer::timeout, this, [this] {
            tick_ = (tick_ + 1) % 200;
            data_.erase(data_.begin());
            const double v = 96.0 + 3.0 * std::sin(tick_ * 0.17) + 2.0 * std::cos(tick_ * 0.29 + 0.8);
            data_.push_back(std::clamp(v, 88.0, 100.0));
            update();
        });
        timer->start();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const int W = width(), H = height();
        const int n = static_cast<int>(data_.size());
        if (n < 2) return;

        constexpr double D_MIN = 86.0, D_MAX = 102.0;

        // Subtle grid
        p.setPen(QPen(QColor(255, 170, 90, 13), 1));
        for (int g = 0; g <= 3; ++g)
            p.drawLine(0, H * g / 3, W, H * g / 3);

        // Y labels
        QFont lf; lf.setPointSize(6);
        p.setFont(lf);
        p.setPen(QColor(107, 84, 68));
        p.drawText(QRect(0, 0, 20, 10), Qt::AlignLeft, "100");
        p.drawText(QRect(0, H / 2 - 5, 20, 10), Qt::AlignLeft, "94");
        p.drawText(QRect(0, H - 10, 20, 10), Qt::AlignLeft, "88");

        const int ox = 22, ow = W - ox - 3;

        // X-axis labels at ends
        p.drawText(QRect(ox, H - 10, 30, 10), Qt::AlignLeft, "00:00");
        p.drawText(QRect(W - 30, H - 10, 30, 10), Qt::AlignRight, "22:00");

        // Score line
        QPainterPath line;
        for (int i = 0; i < n; ++i) {
            const double x = ox + ow * i / (n - 1.0);
            const double norm = (data_[static_cast<std::size_t>(i)] - D_MIN) / (D_MAX - D_MIN);
            const double y = (H - 12) - norm * (H - 12) + 1;
            if (i == 0) line.moveTo(x, y); else line.lineTo(x, y);
        }
        p.setPen(QPen(QColor(255, 183, 102), 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.setBrush(Qt::NoBrush);
        p.drawPath(line);
    }

private:
    std::vector<double> data_;
    int tick_ = 0;
};

// ─── helpers ──────────────────────────────────────────────────────────────────
namespace {

QString SeverityToQString(avcore::Severity s) {
    return QString::fromUtf8(avcore::ToString(s).data());
}

QString TimePointToQString(std::chrono::system_clock::time_point tp) {
    const auto t = std::chrono::system_clock::to_time_t(tp);
    return QDateTime::fromSecsSinceEpoch(static_cast<qint64>(t)).toString("yyyy-MM-dd HH:mm:ss");
}

QColor SeverityColor(avcore::Severity s) {
    switch (s) {
        case avcore::Severity::Malicious: return QColor("#FF5A6A");
        case avcore::Severity::Suspicious: return QColor("#FF9B3D");
        case avcore::Severity::Info: return QColor("#C7B6A2");
    }
    return QColor("#C7B6A2");
}

QWidget* MakeStatCard(const QString& caption, QLabel** out_value_label) {
    auto* card = new QFrame();
    card->setObjectName("StatCard");
    auto* layout = new QVBoxLayout(card);
    layout->setContentsMargins(14, 12, 14, 12);

    auto* value_label = new QLabel("0", card);
    value_label->setStyleSheet("font-size: 24pt; font-weight: 700; color: #ffffff;");
    layout->addWidget(value_label);

    auto* caption_label = new QLabel(caption, card);
    caption_label->setStyleSheet("color: #C7B6A2; font-size: 8.5pt;");
    layout->addWidget(caption_label);

    *out_value_label = value_label;
    return card;
}

QWidget* MakeStatusCircle(QFrame** out_frame, QLabel** out_icon) {
    auto* circle = new PulseStatusCircle();
    circle->setObjectName("StatusCircle");
    circle->setFixedSize(168, 168);

    auto* wrapper = new QWidget();
    auto* wrapper_layout = new QHBoxLayout(wrapper);
    wrapper_layout->setContentsMargins(0, 0, 0, 0);
    wrapper_layout->addStretch();
    wrapper_layout->addWidget(circle);
    wrapper_layout->addStretch();

    *out_frame = circle;
    *out_icon = nullptr; // icon drawn directly in PulseStatusCircle::paintEvent
    return wrapper;
}

QPushButton* MakeQuickTile(const QString& emoji, const QString& label) {
    auto* button = new CyberTile(emoji + "\n" + label);
    button->setObjectName("QuickTile");
    button->setFixedSize(112, 80);
    button->setCursor(Qt::PointingHandCursor);
    return button;
}

QGroupBox* MakeGroup(const QString& title) {
    return new QGroupBox(title);
}

} // namespace

// Startup step tracer -- no-op in shipped builds. (Previously appended to a
// hardcoded developer path C:\Users\<dev>\...\avdbg.txt, which both leaked the
// developer's username into the binary and wrote a stray file on every launch.)
static void CtorDbg(const char* /*step*/) {}

MainWindow::MainWindow(avcore::Config config, QWidget* parent)
    : QMainWindow(parent), config_(std::move(config)) {
    setWindowTitle(QString::fromUtf8("TeoAvSuite"));

    // Open at a comfortable size that always fits the current screen, and
    // center it. minimumSize keeps the layout usable when shrunk; the window
    // stays freely resizable (and maximizable) from there. Prevents the old
    // fixed 1140x720 from spilling off-screen on high-DPI / secondary monitors.
    setMinimumSize(820, 560);
    if (QScreen* screen = QApplication::primaryScreen()) {
        const QRect avail = screen->availableGeometry();
        const int w = qBound(820, static_cast<int>(avail.width() * 0.85), 1200);
        const int h = qBound(560, static_cast<int>(avail.height() * 0.85), 800);
        resize(w, h);
        move(avail.x() + (avail.width() - w) / 2,
             avail.y() + (avail.height() - h) / 2);
    } else {
        resize(1140, 720);
    }
    CtorDbg("enter");

    engine_ = std::make_unique<avengine::Engine>(config_, [this](const avcore::DetectionEvent& event) {
        QMetaObject::invokeMethod(this, [this, event] { AppendDetectionRow(event); }, Qt::QueuedConnection);
    });
    CtorDbg("engine created");

    auto* central = new QWidget(this);
    auto* root_layout = new QHBoxLayout(central);
    root_layout->setContentsMargins(0, 0, 0, 0);
    root_layout->setSpacing(0);

    root_layout->addWidget(BuildSidebar());
    CtorDbg("sidebar");

    pages_ = new QStackedWidget(central);
    pages_->addWidget(BuildHomePage());       CtorDbg("home");     // 0
    pages_->addWidget(BuildHistoryPage());    CtorDbg("history");  // 1
    pages_->addWidget(BuildQuarantinePage()); CtorDbg("quarantine"); // 2
    pages_->addWidget(BuildInvestigationPage(this)); CtorDbg("investigation"); // 3
    root_layout->addWidget(pages_, /*stretch=*/1);

    setCentralWidget(central);
    CtorDbg("central set");

    SetupTrayIcon();     CtorDbg("tray");
    RefreshHomeStats();  CtorDbg("home stats");
    LoadHistory();       CtorDbg("history loaded");

    // Wire ETW raw events into the ETW monitor page before starting realtime.
    // If command_line is empty (ETW provider limitation), read it from the new
    // process PEB before handing off to the UI thread.
    engine_->SetEtwRawCallback([this](const avbehavior::ProcessEvent& event_in) {
        avbehavior::ProcessEvent event = event_in;
        if (event.command_line.empty() && event.process_id != 0) {
            // Read command line from target process PEB
            HANDLE h = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                static_cast<DWORD>(event.process_id));
            if (h) {
                using PFN_NtQIP = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS,
                                                    PVOID, ULONG, PULONG);
                static auto NtQIP = reinterpret_cast<PFN_NtQIP>(
                    GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                   "NtQueryInformationProcess"));
                if (NtQIP) {
                    PROCESS_BASIC_INFORMATION pbi{}; ULONG ret = 0;
                    if (NtQIP(h, ProcessBasicInformation, &pbi, sizeof(pbi), &ret) == 0
                        && pbi.PebBaseAddress) {
                        PEB peb{};
                        RTL_USER_PROCESS_PARAMETERS params{};
                        SIZE_T rd = 0;
                        if (ReadProcessMemory(h, pbi.PebBaseAddress, &peb, sizeof(peb), &rd)
                            && peb.ProcessParameters
                            && ReadProcessMemory(h, peb.ProcessParameters,
                                                 &params, sizeof(params), &rd)
                            && params.CommandLine.Length > 0
                            && params.CommandLine.Buffer) {
                            std::wstring wc(params.CommandLine.Length / 2, L'\0');
                            if (ReadProcessMemory(h, params.CommandLine.Buffer,
                                                  wc.data(), params.CommandLine.Length, &rd)) {
                                const int n = WideCharToMultiByte(
                                    CP_UTF8, 0, wc.c_str(), -1,
                                    nullptr, 0, nullptr, nullptr);
                                if (n > 1) {
                                    event.command_line.resize(n - 1);
                                    WideCharToMultiByte(CP_UTF8, 0, wc.c_str(), -1,
                                        event.command_line.data(), n, nullptr, nullptr);
                                }
                            }
                        }
                    }
                }
                CloseHandle(h);
            }
        }
        QMetaObject::invokeMethod(this, [this, event] { AppendEtwRow(event); },
                                  Qt::QueuedConnection);
    });
    CtorDbg("before StartRealtimeProtection");
    engine_->StartRealtimeProtection();
    CtorDbg("after StartRealtimeProtection");

    // After 2 s, any component whose status hasn't been updated by a SYS.*
    // event is assumed healthy and shown as "Hoạt động".
    auto* init_timer = new QTimer(this);
    init_timer->setSingleShot(true);
    connect(init_timer, &QTimer::timeout, this, [this] {
        auto finalizeLabel = [](QLabel* lbl, const QString& name) {
            if (lbl && lbl->property("statusSet").toBool() == false) {
                lbl->setText(QString::fromUtf8("● %1  Hoạt động").arg(name));
                lbl->setStyleSheet("color: #4ADE80; font-weight: 600;");
            }
        };
        finalizeLabel(folder_watch_status_, QString::fromUtf8("Folder Watch"));
        finalizeLabel(etw_monitor_status_,  QString::fromUtf8("ETW Monitor"));
        finalizeLabel(driver_status_,       QString::fromUtf8("Driver Block"));
        // Net monitor always starts active
        if (net_monitor_status_ && !net_monitor_status_->property("statusSet").toBool()) {
            net_monitor_status_->setText(QString::fromUtf8("\xe2\x97\x8f Net Monitor"));
            net_monitor_status_->setStyleSheet(
                "color:#FF7A00;font-weight:600;font-size:7.5pt;background:transparent;");
            net_monitor_status_->setProperty("statusSet", true);
        }
    });
    init_timer->start(2000);
}

MainWindow::~MainWindow() = default;

void MainWindow::closeEvent(QCloseEvent* event) {
    if (tray_icon_ && tray_icon_->isVisible()) {
        hide();
        tray_icon_->showMessage(
            "TeoAvSuite",
            QString::fromUtf8("TeoAvSuite vẫn đang chạy trong khay hệ thống. "
                               "Double-click để mở lại."),
            QSystemTrayIcon::Information, 3000);
        event->ignore();
    } else {
        event->accept();
    }
}

static QIcon MakeTrayIcon(bool threat) {
    QPixmap pm(32, 32);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);

    // Draw a simple shield shape filled with green (safe) or red (threat)
    const QColor fill = threat ? QColor(0xFF, 0x5A, 0x6A) : QColor(0x4A, 0xDE, 0x80);
    QPainterPath shield;
    shield.moveTo(16, 2);
    shield.lineTo(30, 7);
    shield.lineTo(30, 18);
    shield.cubicTo(30, 26, 22, 30, 16, 32);
    shield.cubicTo(10, 30,  2, 26,  2, 18);
    shield.lineTo(2, 7);
    shield.closeSubpath();

    p.setPen(Qt::NoPen);
    p.setBrush(fill);
    p.drawPath(shield);

    // Small white symbol in the middle
    p.setPen(QPen(Qt::white, 2.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    if (threat) {
        // Exclamation mark
        p.drawLine(QPointF(16, 10), QPointF(16, 19));
        p.setPen(Qt::NoPen);
        p.setBrush(Qt::white);
        p.drawEllipse(QPointF(16, 23), 2.0, 2.0);
    } else {
        // Checkmark
        QPainterPath ck;
        ck.moveTo(10, 18);
        ck.lineTo(14, 23);
        ck.lineTo(22, 13);
        p.setBrush(Qt::NoBrush);
        p.drawPath(ck);
    }

    return QIcon(pm);
}

void MainWindow::SetupTrayIcon() {
    tray_icon_ = new QSystemTrayIcon(MakeTrayIcon(false), this);
    tray_icon_->setToolTip(QString::fromUtf8("TeoAvSuite - Đang bảo vệ"));

    auto* menu = new QMenu(this);

    auto* open_action = new QAction(QString::fromUtf8("Mở TeoAvSuite"), this);
    connect(open_action, &QAction::triggered, this, [this] {
        showNormal();
        activateWindow();
    });
    menu->addAction(open_action);
    menu->addSeparator();

    auto* quit_action = new QAction(QString::fromUtf8("Thoát"), this);
    connect(quit_action, &QAction::triggered, this, [] { QApplication::quit(); });
    menu->addAction(quit_action);

    tray_icon_->setContextMenu(menu);
    connect(tray_icon_, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason reason) {
                if (reason == QSystemTrayIcon::DoubleClick) {
                    showNormal();
                    activateWindow();
                }
            });

    tray_icon_->show();
}

void MainWindow::ShowThreatNotification(const avcore::DetectionEvent& event) {
    if (!tray_icon_) return;
    tray_icon_->showMessage(
        QString::fromUtf8("TeoAvSuite - Phát hiện mối nguy hiểm!"),
        QString::fromUtf8("Rule: %1\nFile: %2")
            .arg(QString::fromUtf8(event.rule_id.c_str()),
                 QString::fromUtf8(event.target_path.c_str())),
        QSystemTrayIcon::Critical, 6000);
}

QWidget* MainWindow::BuildSidebar() {
    // Figma sidebar: 220px rail, logo header ("AvSuite" + PRO badge), three
    // collapsible labeled sections (Protection / Monitoring / Advanced), and
    // Settings pinned at the bottom under a hairline.
    auto* sidebar = new QWidget();
    sidebar->setObjectName("Sidebar");
    sidebar->setFixedWidth(220);

    auto* layout = new QVBoxLayout(sidebar);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // ── Logo header ──
    {
        auto* logo_bar = new QFrame(sidebar);
        logo_bar->setObjectName("SidebarLogoBar");
        logo_bar->setStyleSheet(
            "QFrame#SidebarLogoBar { background: transparent;"
            " border: none; border-bottom: 1px solid #493826; }");
        auto* lb = new QHBoxLayout(logo_bar);
        lb->setContentsMargins(16, 16, 16, 12);
        lb->setSpacing(10);

        auto* logo_w = new QWidget(logo_bar);
        logo_w->setFixedSize(28, 28);
        logo_w->setStyleSheet(
            "QWidget { background: #FF7A00; border: none; border-radius: 8px; }");
        {
            auto* cl = new QVBoxLayout(logo_w);
            cl->setContentsMargins(0, 0, 0, 0);
            cl->addWidget(new IconWidget(IconWidget::ShieldCheck, 16,
                                         QColor(0x12, 0x0B, 0x06), logo_w),
                          0, Qt::AlignCenter);
        }
        lb->addWidget(logo_w);

        auto* name = new QLabel("AvSuite", logo_bar);
        name->setStyleSheet(
            "font-size: 15px; font-weight: 700; color: #ECE4DA;"
            " background: transparent; border: none;");
        lb->addWidget(name);
        lb->addStretch();

        auto* pro = new QLabel("PRO", logo_bar);
        pro->setStyleSheet(
            "QLabel { background: #2E1D10; color: #FF7A00; border: none;"
            " border-radius: 4px; padding: 1px 6px; font-size: 10px;"
            " font-weight: 700; font-family: 'Cascadia Code', Consolas, monospace; }");
        lb->addWidget(pro);
        layout->addWidget(logo_bar);
    }

    nav_group_ = new QButtonGroup(sidebar);

    struct NavEntry {
        IconWidget::Type icon;
        int page_index;
        QString label;
    };

    // Creates one nav row: icon at the left, label text via QSS padding.
    auto makeNavButton = [this](const NavEntry& entry, QWidget* parent) -> QPushButton* {
        QPushButton* button;
        if (entry.page_index == 1) {
            auto* bb = new BadgeButton(entry.label, parent);
            nav_history_btn_ = bb;
            button = bb;
        } else {
            auto* rb = new RippleButton(entry.label, parent);
            rb->setRippleColor(QColor(255, 122, 0, 70));
            button = rb;
        }
        button->setObjectName("NavButton");
        button->setCheckable(true);
        button->setFixedHeight(32);
        button->setCursor(Qt::PointingHandCursor);

        // Icon sits in a small rounded tile (active = amber) so the rail reads
        // like a modern app nav instead of bare, thin line-art.
        auto* icoBox = new QWidget(button);
        icoBox->setObjectName("NavIcoBox");
        icoBox->setAttribute(Qt::WA_TransparentForMouseEvents);
        icoBox->setAttribute(Qt::WA_StyledBackground, true);
        icoBox->setFixedSize(26, 26);
        icoBox->move(9, (32 - 26) / 2);
        auto icoBoxQss = [](bool on) {
            return QString("QWidget#NavIcoBox{border-radius:7px;background:%1;}")
                .arg(on ? "rgba(255,122,0,0.18)" : "rgba(255,170,90,0.05)");
        };
        icoBox->setStyleSheet(icoBoxQss(false));
        auto* ico = new IconWidget(entry.icon, 15, QColor(0xC7, 0xB6, 0xA2), icoBox);
        ico->setAttribute(Qt::WA_TransparentForMouseEvents);
        ico->move((26 - ico->width()) / 2, (26 - ico->height()) / 2);
        connect(button, &QPushButton::toggled, button, [ico, icoBox, icoBoxQss](bool checked) {
            ico->setColor(checked ? QColor(0xFF, 0x7A, 0x00) : QColor(0xC7, 0xB6, 0xA2));
            icoBox->setStyleSheet(icoBoxQss(checked));
        });

        nav_group_->addButton(button, entry.page_index);
        connect(button, &QPushButton::clicked, this,
                [this, index = entry.page_index] { GoToPage(index); });
        return button;
    };

    struct NavSection {
        QString label;
        bool collapsed;
        std::vector<NavEntry> items;
    };
    const NavSection sections[] = {
        {"CORE", false, {
            {IconWidget::Home,          0,  "Home"},
            {IconWidget::Search,        1,  "History"},
            {IconWidget::Archive,       2,  "Quarantine"},
            {IconWidget::Layers,        3,  "Investigation"},
        }},
    };

    // Nav lives in a scroll area so every entry stays reachable on short windows.
    auto* nav_scroll = new QScrollArea(sidebar);
    nav_scroll->setWidgetResizable(true);
    nav_scroll->setFrameShape(QFrame::NoFrame);
    nav_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    nav_scroll->setStyleSheet(
        "QScrollArea { background:transparent; border:none; }"
        "QScrollBar:vertical { background:transparent; width:3px; }"
        "QScrollBar::handle:vertical { background:rgba(255,170,90,60); border-radius:1px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }");
    auto* nav_inner = new QWidget();
    nav_inner->setStyleSheet("background:transparent;");
    auto* nav_l = new QVBoxLayout(nav_inner);
    nav_l->setContentsMargins(0, 8, 0, 8);
    nav_l->setSpacing(1);

    for (const auto& section : sections) {
        // Section header — uppercase label + chevron, click to collapse.
        auto* head = new QPushButton(nav_inner);
        head->setObjectName("NavSection");
        head->setCursor(Qt::PointingHandCursor);
        head->setFixedHeight(26);
        auto* hl = new QHBoxLayout(head);
        hl->setContentsMargins(12, 0, 12, 0);
        auto* hlbl = new QLabel(section.label, head);
        hlbl->setObjectName("NavSectionLabel");
        hlbl->setAttribute(Qt::WA_TransparentForMouseEvents);
        auto* chev = new QLabel(section.collapsed ? QString::fromUtf8("▸")
                                                  : QString::fromUtf8("▾"), head);
        chev->setObjectName("NavSectionLabel");
        chev->setAttribute(Qt::WA_TransparentForMouseEvents);
        hl->addWidget(hlbl);
        hl->addStretch();
        hl->addWidget(chev);
        nav_l->addWidget(head);

        auto* body = new QWidget(nav_inner);
        body->setStyleSheet("background: transparent;");
        auto* bl = new QVBoxLayout(body);
        bl->setContentsMargins(0, 0, 0, 4);
        bl->setSpacing(1);
        for (const auto& entry : section.items)
            bl->addWidget(makeNavButton(entry, body));
        body->setVisible(!section.collapsed);
        nav_l->addWidget(body);

        connect(head, &QPushButton::clicked, body, [body, chev] {
            // Animated expand/collapse: slide the section body open/closed by
            // animating maximumHeight (240ms OutCubic), Figma-style.
            const bool show = !body->isVisible() || body->maximumHeight() == 0;
            chev->setText(show ? QString::fromUtf8("▾") : QString::fromUtf8("▸"));
            auto* anim = new QPropertyAnimation(body, "maximumHeight", body);
            // AnimMs() collapses this to 0 (instant, no per-frame relayout) on
            // low-end/old hardware; full 240ms OutCubic slide on capable machines.
            anim->setDuration(avdashboard::AnimMs(240));
            anim->setEasingCurve(QEasingCurve::OutCubic);
            if (show) {
                body->setMaximumHeight(0);
                body->setVisible(true);
                anim->setStartValue(0);
                anim->setEndValue(body->sizeHint().height());
                QObject::connect(anim, &QPropertyAnimation::finished, body, [body] {
                    body->setMaximumHeight(QWIDGETSIZE_MAX);
                });
            } else {
                anim->setStartValue(body->height());
                anim->setEndValue(0);
                QObject::connect(anim, &QPropertyAnimation::finished, body, [body] {
                    body->setVisible(false);
                    body->setMaximumHeight(QWIDGETSIZE_MAX);
                });
            }
            anim->start(QAbstractAnimation::DeleteWhenStopped);
        });
    }

    nav_l->addStretch();
    nav_scroll->setWidget(nav_inner);
    layout->addWidget(nav_scroll, 1);

    nav_group_->button(0)->setChecked(true);

    return sidebar;
}

QWidget* MainWindow::BuildHomePage() {
    auto* page = new QWidget();
    auto* outer = new QHBoxLayout(page);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    // ── Center scrollable column ──────────────────────────────────────────────
    auto* c_scroll = new QScrollArea();
    c_scroll->setWidgetResizable(true);
    c_scroll->setFrameShape(QFrame::NoFrame);
    c_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    c_scroll->setStyleSheet("QScrollArea { background: transparent; border: none; }");

    auto* c_w = new QWidget();
    c_w->setStyleSheet("QWidget { background: transparent; }");
    auto* c_l = new QVBoxLayout(c_w);
    c_l->setContentsMargins(20, 18, 14, 20);
    c_l->setSpacing(12);

    // ── Header row ────────────────────────────────────────────────────────────
    {
        auto* hr = new QHBoxLayout();
        auto* tc = new QVBoxLayout();
        tc->setSpacing(2);
        auto* title_lbl = new QLabel("Dashboard", c_w);
        title_lbl->setStyleSheet(
            "font-size: 13pt; font-weight: 600; color: #ffffff; background: transparent;");
        auto* date_lbl = new QLabel(
            QDate::currentDate().toString(QString::fromUtf8("dddd, MMMM d"))
                + QString::fromUtf8(" · Cập nhật lúc khởi động"), c_w);
        date_lbl->setStyleSheet("font-size: 8pt; color: #C7B6A2; background: transparent;");
        tc->addWidget(title_lbl);
        tc->addWidget(date_lbl);
        hr->addLayout(tc);
        hr->addStretch();

        auto* sf = new QFrame(c_w);
        sf->setStyleSheet(
            "QFrame { background: #23160C; border: 1px solid rgba(255,170,90,0.12); "
            "border-radius: 10px; }");
        auto* sfl = new QHBoxLayout(sf);
        sfl->setContentsMargins(10, 5, 10, 5);
        sfl->setSpacing(5);
        auto* si = new IconWidget(IconWidget::Search, 12, QColor(0x6B,0x54,0x44), sf);
        auto* sh = new QLabel(QString::fromUtf8("Tìm kiếm nhanh…"), sf);
        sh->setStyleSheet("background: transparent; border: none; font-size: 8.5pt; color: #6B5444;");
        sfl->addWidget(si); sfl->addWidget(sh);
        hr->addWidget(sf);
        c_l->addLayout(hr);
    }

    // ── Shield Status Card ────────────────────────────────────────────────────
    {
        auto* card = new QFrame(c_w);
        card->setObjectName("StatusCircle"); // reuse existing StatusCircle name for RefreshHomeStats
        card->setStyleSheet(
            "QFrame { "
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:1, "
            "  stop:0 #2A1A0C, stop:0.5 #1E1108, stop:1 #1A0F08); "
            "border: 1px solid rgba(255,170,90,0.18); "
            "border-radius: 14px; }");
        auto* hl = new QHBoxLayout(card);
        hl->setContentsMargins(16, 14, 16, 14);
        hl->setSpacing(14);

        auto* shw = new ShieldIconWidget(card);
        shield_widget_ = shw;
        pulse_circle_  = nullptr;
        status_circle_ = nullptr;
        status_icon_label_ = nullptr;
        hl->addWidget(shw);

        // Status text column
        auto* tc = new QVBoxLayout();
        tc->setSpacing(4);

        auto* badge = new QHBoxLayout();
        badge->setSpacing(5);
        auto* bdot = new QLabel(QString::fromUtf8("●"), card);
        bdot->setStyleSheet("color: #4ADE80; font-size: 7pt; background: transparent;");
        auto* btext = new QLabel("Protected", card);
        btext->setStyleSheet(
            "font-size: 8pt; font-weight: 600; color: #4ADE80; background: transparent;");
        badge->addWidget(bdot); badge->addWidget(btext); badge->addStretch();
        tc->addLayout(badge);

        protection_status_label_ = new QLabel(
            QString::fromUtf8("Máy của bạn đang được bảo vệ"), card);
        protection_status_label_->setStyleSheet(
            "font-size: 22pt; font-weight: 800; color: #4ADE80; background: transparent;");
        tc->addWidget(protection_status_label_);

        auto* sub = new QLabel(
            QString::fromUtf8("5/5 shields active · Hash · YARA · ETW behavior"), card);
        sub->setStyleSheet("font-size: 8pt; color: #C7B6A2; background: transparent;");
        shields_sub_label_ = sub;  // updated live by RefreshHomeStats()
        tc->addWidget(sub);

        auto* cr = new QHBoxLayout();
        cr->setSpacing(14);
        auto makeCompLbl = [&](QLabel** out, const QString& name) {
            auto* lbl = new QLabel(QString::fromUtf8("● ") + name, card);
            lbl->setStyleSheet(
                "color: rgba(199,182,162,0.45); font-weight: 600; font-size: 7.5pt; "
                "background: transparent;");
            lbl->setProperty("statusSet", false);
            *out = lbl;
            return lbl;
        };
        cr->addWidget(makeCompLbl(&folder_watch_status_, "Folder Watch"));
        cr->addWidget(makeCompLbl(&etw_monitor_status_, "ETW Monitor"));
        cr->addWidget(makeCompLbl(&driver_status_, "Driver Block"));

        // Network Monitor toggle pill
        {
            auto* net_row = new QHBoxLayout();
            net_row->setSpacing(6);
            net_monitor_status_ = new QLabel(QString::fromUtf8("\xe2\x97\x8f Net Monitor"), card);
            net_monitor_status_->setStyleSheet(
                "color:rgba(199,182,162,0.45);font-weight:600;font-size:7.5pt;background:transparent;");
            net_monitor_status_->setProperty("statusSet", false);
            cr->addWidget(net_monitor_status_);

            auto* toggle_btn = new QPushButton("ON", card);
            toggle_btn->setFixedSize(34, 16);
            toggle_btn->setCheckable(true);
            toggle_btn->setChecked(true);
            const auto applyToggleStyle = [toggle_btn](bool on) {
                toggle_btn->setStyleSheet(on
                    ? "QPushButton{background:#FF7A00;border:none;border-radius:8px;"
                      "color:#fff;font-size:6pt;font-weight:800;"
                      "box-shadow:0 0 6px rgba(255,122,0,0.8);}"
                    : "QPushButton{background:rgba(120,100,80,0.4);border:none;border-radius:8px;"
                      "color:#8A7A6E;font-size:6pt;font-weight:700;}");
                toggle_btn->setText(on ? "ON" : "OFF");
            };
            applyToggleStyle(true);
            connect(toggle_btn, &QPushButton::toggled, this,
                    [this, toggle_btn, applyToggleStyle](bool checked) {
                applyToggleStyle(checked);
                net_monitor_enabled_ = checked;
                if (net_monitor_timer_) {
                    if (checked) net_monitor_timer_->start();
                    else         net_monitor_timer_->stop();
                }
                if (net_monitor_status_) {
                    net_monitor_status_->setText(
                        checked ? QString::fromUtf8("\xe2\x97\x8f Net Monitor")
                                : QString::fromUtf8("\xe2\x97\x8f Net Monitor"));
                    net_monitor_status_->setStyleSheet(checked
                        ? "color:#FF7A00;font-weight:600;font-size:7.5pt;background:transparent;"
                        : "color:rgba(199,182,162,0.35);font-weight:600;font-size:7.5pt;background:transparent;");
                }
            });
            cr->addWidget(toggle_btn);
        }

        cr->addStretch();
        tc->addLayout(cr);
        hl->addLayout(tc, 1);

        // Score ring
        auto* score_w = new ScoreRingWidget(card);
        score_ring_ = score_w;
        auto* score_col = new QVBoxLayout();
        score_col->setSpacing(3);
        score_col->addWidget(score_w, 0, Qt::AlignHCenter);
        auto* score_lbl = new QLabel("Security Score", card);
        score_lbl->setStyleSheet("font-size: 7pt; color: #C7B6A2; background: transparent;");
        score_lbl->setAlignment(Qt::AlignCenter);
        score_col->addWidget(score_lbl);
        hl->addLayout(score_col);

        // Quick Scan button (Zap icon + text)
        auto* qbtn = new QPushButton("  Quick Scan", card);
        auto* qico = new IconWidget(IconWidget::Zap, 13, Qt::white, qbtn);
        qico->setAttribute(Qt::WA_TransparentForMouseEvents);
        qico->move(10, (36 - qico->height()) / 2);
        qbtn->setStyleSheet(
            "QPushButton { background: #FF7A00; color: white; border: none; "
            "border-radius: 10px; padding: 8px 18px 8px 30px; font-size: 9pt; font-weight: 700; }"
            "QPushButton:hover { background: #FF8C20; }"
            "QPushButton:pressed { background: #E06800; }");
        connect(qbtn, &QPushButton::clicked, this, [this] { GoToPage(1); OnScanFolderClicked(); });
        hl->addWidget(qbtn);

        c_l->addWidget(card);
    }

    // ── Stat Row ──────────────────────────────────────────────────────────────
    {
        auto* sr = new QHBoxLayout();
        sr->setSpacing(10);

        struct StatDef {
            QString label; QLabel** ptr;
            IconWidget::Type ico; QColor accent; QString sub;
        };
        StatDef defs[] = {
            {"Threats Blocked", &stat_detections_label_,
             IconWidget::Shield,    QColor(0xFF,0x7A,0x00), QString::fromUtf8("Tổng cộng")},
            {"Files Scanned",   &stat_scans_label_,
             IconWidget::HardDrive, QColor(0xFF,0x9B,0x3D), QString::fromUtf8("Tổng lần quét")},
            {"Quarantined",     &stat_quarantine_label_,
             IconWidget::Archive,   QColor(0x4A,0xDE,0x80), QString::fromUtf8("Đang cách ly")},
        };
        for (auto& d : defs) {
            auto* sc = new QFrame(c_w);
            sc->setObjectName("StatCard");
            auto* sl = new QVBoxLayout(sc);
            sl->setContentsMargins(14, 12, 14, 12);
            sl->setSpacing(5);

            auto* top = new QHBoxLayout();
            auto* cap = new QLabel(d.label, sc);
            cap->setStyleSheet("font-size: 8pt; color: #C7B6A2; background: transparent;");
            top->addWidget(cap, 1);

            // Icon box
            auto* ib_w = new QWidget(sc);
            ib_w->setFixedSize(28, 28);
            QColor bg = d.accent; bg.setAlpha(34);
            ib_w->setStyleSheet(
                QString("QWidget { background: rgba(%1,%2,%3,%4); border-radius: 7px; }")
                    .arg(d.accent.red()).arg(d.accent.green()).arg(d.accent.blue()).arg(34));
            auto* ib = new IconWidget(d.ico, 14, d.accent, ib_w);
            ib->move((28-ib->width())/2, (28-ib->height())/2);
            top->addWidget(ib_w);
            sl->addLayout(top);

            auto* val = new QLabel("0", sc);
            val->setStyleSheet(
                "font-size: 20pt; font-weight: 600; color: #ffffff; background: transparent;");
            sl->addWidget(val);
            *d.ptr = val;

            auto* sub = new QLabel(d.sub, sc);
            sub->setStyleSheet("font-size: 7.5pt; color: #C7B6A2; background: transparent;");
            sl->addWidget(sub);

            sr->addWidget(sc, 1);
        }
        stat_malicious_label_ = new QLabel("0", c_w);
        stat_malicious_label_->hide();
        c_l->addLayout(sr);
    }

    // ── Quick actions (Figma layout) ──────────────────────────────────────────
    {
        auto* qa = new QHBoxLayout();
        qa->setSpacing(10);
        struct QAct { IconWidget::Type ico; QString label; int page; };
        const QAct acts[] = {
            {IconWidget::Archive, QString::fromUtf8("Open Quarantine"), 2},
            {IconWidget::Bell,    QString::fromUtf8("View Alerts"),     25},
            {IconWidget::Ai,      QString::fromUtf8("AI Assistant"),    6},
            {IconWidget::Eye,     QString::fromUtf8("Threat Intel"),    17},
        };
        for (const auto& a : acts) {
            auto* btn = new QPushButton(c_w);
            btn->setObjectName("QuickAct");
            btn->setFixedHeight(52);
            btn->setCursor(Qt::PointingHandCursor);
            btn->setStyleSheet(
                "QPushButton#QuickAct { background: #23160C; border: 1px solid #493826; "
                "border-radius: 14px; text-align: left; padding: 0 14px 0 44px; "
                "color: #C7B6A2; font-size: 9.5pt; font-weight: 500; }"
                "QPushButton#QuickAct:hover { border: 1px solid #FF7A00; color: #ECE4DA; }");
            btn->setText(a.label);
            auto* ic = new IconWidget(a.ico, 15, QColor(0xFF,0x7A,0x00), btn);
            ic->setAttribute(Qt::WA_TransparentForMouseEvents);
            ic->move(16, (52 - ic->height()) / 2);
            const int pg = a.page;
            connect(btn, &QPushButton::clicked, this, [this, pg] { GoToPage(pg); });
            qa->addWidget(btn, 1);
        }
        c_l->addLayout(qa);
    }

    // ── Scan Modules (kept, wired to real scans) ───────────────────────────────
    {
        auto* mh = new QHBoxLayout();
        auto* mt = new QLabel(QString::fromUtf8("Scan Modules"), c_w);
        mt->setStyleSheet("font-size: 10pt; font-weight: 600; color: #ECE4DA; background: transparent;");
        mh->addWidget(mt);
        mh->addStretch();
        c_l->addLayout(mh);

        auto* mg = new QGridLayout();
        mg->setSpacing(8);

        struct ModDef { IconWidget::Type ico; QString label; QColor color; };
        const ModDef mods[] = {
            {IconWidget::Folder,   QString::fromUtf8("Folder"),      QColor(0xFF,0x9B,0x3D)},
            {IconWidget::File,     QString::fromUtf8("File"),        QColor(0xFF,0xB7,0x66)},
            {IconWidget::Database, QString::fromUtf8("Registry"),    QColor(0xFF,0x7A,0x00)},
            {IconWidget::Cpu,      QString::fromUtf8("Memory"),      QColor(0xFF,0x9B,0x3D)},
            {IconWidget::Link,     QString::fromUtf8("Persistence"), QColor(0xFF,0xB7,0x66)},
            {IconWidget::Archive,  QString::fromUtf8("Quarantine"),  QColor(0x4A,0xDE,0x80)},
        };
        const std::vector<std::function<void()>> mod_actions = {
            [this]{ GoToPage(1); OnScanFolderClicked(); },
            [this]{ GoToPage(1); OnScanFilesClicked(); },
            [this]{ GoToPage(1); OnScanRegistryClicked(); },
            [this]{ GoToPage(1); OnScanMemoryClicked(); },
            [this]{ GoToPage(1); OnScanPersistenceClicked(); },
            [this]{ GoToPage(2); },
        };

        for (int i = 0; i < 6; ++i) {
            const auto& m = mods[i];
            auto* btn = new QPushButton(c_w);
            btn->setObjectName("ModuleTile");
            btn->setStyleSheet(
                "QPushButton#ModuleTile { background: #2E1D10; "
                "border: 1px solid rgba(255,170,90,0.10); border-radius: 12px; }"
                "QPushButton#ModuleTile:hover { background: rgba(255,122,0,0.08); "
                "border: 1px solid rgba(255,122,0,0.25); }"
                "QPushButton#ModuleTile:pressed { background: rgba(255,122,0,0.15); }");
            btn->setFixedHeight(80);
            btn->setCursor(Qt::PointingHandCursor);
            connect(btn, &QPushButton::clicked, this, [cb = mod_actions[static_cast<size_t>(i)]] { cb(); });

            auto* bl = new QVBoxLayout(btn);
            bl->setContentsMargins(11, 10, 11, 10);
            bl->setSpacing(7);

            // Icon box row
            auto* ico_row = new QHBoxLayout();
            ico_row->setContentsMargins(0,0,0,0);
            auto* ic_w = new QWidget(btn);
            ic_w->setAttribute(Qt::WA_TransparentForMouseEvents);
            ic_w->setFixedSize(30, 28);
            QColor bg = m.color; bg.setAlpha(30);
            ic_w->setStyleSheet(
                QString("QWidget { background: rgba(%1,%2,%3,30); border-radius: 7px; }")
                    .arg(m.color.red()).arg(m.color.green()).arg(m.color.blue()));
            auto* ic = new IconWidget(m.ico, 14, m.color, ic_w);
            ic->setAttribute(Qt::WA_TransparentForMouseEvents);
            ic->move((30-ic->width())/2, (28-ic->height())/2);
            ico_row->addWidget(ic_w);
            ico_row->addStretch();
            bl->addLayout(ico_row);

            auto* nl = new QLabel(m.label, btn);
            nl->setAttribute(Qt::WA_TransparentForMouseEvents);
            nl->setStyleSheet(
                "font-size: 8.5pt; font-weight: 500; color: #C7B6A2; background: transparent;");
            bl->addWidget(nl);

            mg->addWidget(btn, i / 3, i % 3);
        }
        c_l->addLayout(mg);
    }

    // ── Recent activity (Figma single-column) ─────────────────────────────────
    {
        auto* rc = new QFrame(c_w);
        rc->setStyleSheet("QFrame { background: #23160C; border: 1px solid #493826; border-radius: 14px; }");
        auto* rl = new QVBoxLayout(rc);
        rl->setContentsMargins(0, 0, 0, 6);
        rl->setSpacing(0);

        auto* rh = new QWidget(rc);
        rh->setStyleSheet("QWidget { background: transparent; border-bottom: 1px solid #493826; }");
        auto* rhl = new QHBoxLayout(rh);
        rhl->setContentsMargins(16, 12, 16, 12);
        auto* rt = new QLabel(QString::fromUtf8("Recent activity"), rh);
        rt->setStyleSheet("font-size: 11pt; font-weight: 600; color: #ECE4DA; background: transparent; border: none;");
        rhl->addWidget(rt);
        rhl->addStretch();
        auto* va = new QPushButton(QString::fromUtf8("View all"), rh);
        va->setCursor(Qt::PointingHandCursor);
        va->setStyleSheet(
            "QPushButton { background: transparent; color: #FF7A00; border: none; font-size: 9pt; padding: 0; }"
            "QPushButton:hover { color: #FF9B3D; }");
        connect(va, &QPushButton::clicked, this, [this] { GoToPage(1); });
        rhl->addWidget(va);
        rl->addWidget(rh);

        auto* body = new QWidget(rc);
        body->setStyleSheet("QWidget { background: transparent; border: none; }");
        auto* body_l = new QVBoxLayout(body);
        body_l->setContentsMargins(10, 8, 10, 4);
        home_detections_layout_ = new QVBoxLayout();
        home_detections_layout_->setSpacing(6);
        auto* ph = new QLabel(QString::fromUtf8("Chưa có phát hiện nào"), body);
        ph->setStyleSheet("font-size: 9pt; color: #8B7355; background: transparent; border: none;");
        ph->setAlignment(Qt::AlignCenter);
        home_detections_layout_->addWidget(ph);
        body_l->addLayout(home_detections_layout_);
        rl->addWidget(body);

        c_l->addWidget(rc);
    }

    c_l->addStretch();
    c_scroll->setWidget(c_w);
    outer->addWidget(c_scroll, 1);

    return page;
}

QWidget* MainWindow::BuildQuarantinePage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(28, 28, 28, 28);
    layout->setSpacing(12);

    // Header: title + subtitle + ghost "Export list" action (Figma layout)
    auto* export_btn = new QPushButton(QString::fromUtf8("⭱  Export list"), page);
    export_btn->setObjectName("SelectButton");
    export_btn->setCursor(Qt::PointingHandCursor);
    layout->addWidget(theme::BuildPageHeader(
        QString::fromUtf8("Quarantine"),
        QString::fromUtf8("Các tệp bị cách ly — khôi phục hoặc xóa vĩnh viễn"),
        export_btn));

    // Batch action bar — only visible while rows are selected
    auto* batch_bar = new QFrame(page);
    batch_bar->setObjectName("QuarBatchBar");
    batch_bar->setStyleSheet(
        "QFrame#QuarBatchBar { background: rgba(255,122,0,0.08);"
        " border: 1px solid rgba(255,122,0,0.25); border-radius: 8px; }"
        "QFrame#QuarBatchBar QLabel { background: transparent; border: none; }");
    auto* bb = new QHBoxLayout(batch_bar);
    bb->setContentsMargins(16, 8, 12, 8);
    bb->setSpacing(10);
    auto* sel_lbl = new QLabel(batch_bar);
    sel_lbl->setStyleSheet(QString("color:%1; font-size:12px;").arg(theme::Accent));
    bb->addWidget(sel_lbl, 1);
    auto* restore_button = new QPushButton(QString::fromUtf8("↩  Restore"), batch_bar);
    restore_button->setObjectName("SuccessButton");
    auto* delete_button = new QPushButton(QString::fromUtf8("   X\xc3\xb3" "a v\xc4\xa9nh vi\xe1\xbb\x85n"), batch_bar);
    delete_button->setObjectName("DangerButton");
    {
        auto* di = new IconWidget(IconWidget::Archive, 13, QColor(0xC7,0xB6,0xA2), delete_button);
        di->setAttribute(Qt::WA_TransparentForMouseEvents);
        di->move(9, 8);
    }
    auto* clear_sel_btn = new QPushButton(QString::fromUtf8("✕"), batch_bar);
    clear_sel_btn->setObjectName("SelectButton");
    clear_sel_btn->setFixedWidth(30);
    clear_sel_btn->setToolTip(QString::fromUtf8("Bỏ chọn tất cả"));
    bb->addWidget(restore_button);
    bb->addWidget(delete_button);
    bb->addWidget(clear_sel_btn);
    batch_bar->setVisible(false);
    layout->addWidget(batch_bar);

    // Toolbar: search + Select All + live item count
    auto* toolbar = new QHBoxLayout();
    toolbar->setSpacing(8);
    auto* search_box = new QLineEdit(page);
    search_box->setPlaceholderText(QString::fromUtf8("Tìm trong quarantine…"));
    search_box->setClearButtonEnabled(true);
    search_box->setMaximumWidth(300);
    search_box->setStyleSheet(QString(
        "QLineEdit { background:%1; color:%2; border:1px solid %3;"
        " border-radius:8px; padding:6px 10px; font-size:12px; }")
        .arg(theme::Surface, theme::Text, theme::Border));
    auto* select_all_button = new QPushButton(QString::fromUtf8("✓ Select All"), page);
    select_all_button->setObjectName("SelectButton");
    auto* count_lbl = new QLabel(page);
    count_lbl->setStyleSheet(QString("color:%1; font-size:12px; background:transparent;").arg(theme::Dim));
    toolbar->addWidget(search_box, 1);
    toolbar->addWidget(select_all_button);
    toolbar->addStretch();
    toolbar->addWidget(count_lbl);
    layout->addLayout(toolbar);

    // Table — col 0 keeps the quarantine ID for the action slots but stays hidden
    quarantine_table_ = new QTableWidget(0, 5, page);
    quarantine_table_->setHorizontalHeaderLabels(
        {"ID", QString::fromUtf8("Tên tệp"), QString::fromUtf8("Threat / Rule"),
         QString::fromUtf8("Thời điểm"), QString::fromUtf8("Đường dẫn gốc")});
    {
        auto* qhdr = quarantine_table_->horizontalHeader();
        qhdr->setStretchLastSection(false);
        qhdr->setSectionResizeMode(1, QHeaderView::ResizeToContents); // file name
        qhdr->setSectionResizeMode(2, QHeaderView::ResizeToContents); // rule
        qhdr->setSectionResizeMode(3, QHeaderView::ResizeToContents); // time
        qhdr->setSectionResizeMode(4, QHeaderView::Stretch);          // path takes remaining width
    }
    quarantine_table_->setColumnHidden(0, true);
    quarantine_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    quarantine_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    quarantine_table_->setSelectionMode(QAbstractItemView::MultiSelection);
    quarantine_table_->verticalHeader()->setVisible(false);
    quarantine_table_->setStyleSheet(theme::TableQss());
    // Elide long paths in the middle so the drive root AND the filename stay
    // visible (e.g. "C:\Users\…\dropper.dll"); full path is on the tooltip.
    quarantine_table_->setTextElideMode(Qt::ElideMiddle);
    layout->addWidget(quarantine_table_);

    connect(select_all_button, &QPushButton::clicked, this, &MainWindow::OnSelectAllQuarantineClicked);
    connect(restore_button, &QPushButton::clicked, this, &MainWindow::OnRestoreQuarantineClicked);
    connect(delete_button, &QPushButton::clicked, this, &MainWindow::OnDeleteQuarantineClicked);
    connect(clear_sel_btn, &QPushButton::clicked, page,
            [this] { quarantine_table_->clearSelection(); });

    // Search filter + item count, re-applied whenever rows change (coalesced so a
    // full ReloadQuarantineTable only triggers one pass).
    auto* upd = new QTimer(page);
    upd->setSingleShot(true);
    upd->setInterval(0);
    connect(upd, &QTimer::timeout, page, [this, search_box, count_lbl] {
        const QString q = search_box->text().trimmed();
        int visible = 0;
        for (int r = 0; r < quarantine_table_->rowCount(); ++r) {
            auto* id_item = quarantine_table_->item(r, 0);
            const bool msg_row = (id_item == nullptr);  // empty-state row has no ID cell
            bool show = true;
            if (!msg_row && !q.isEmpty()) {
                auto txt = [this, r](int c) {
                    auto* it = quarantine_table_->item(r, c);
                    return it ? it->text() : QString();
                };
                show = txt(1).contains(q, Qt::CaseInsensitive) ||
                       txt(2).contains(q, Qt::CaseInsensitive) ||
                       txt(4).contains(q, Qt::CaseInsensitive);
            }
            quarantine_table_->setRowHidden(r, !show);
            if (show && !msg_row) ++visible;
        }
        count_lbl->setText(QString::fromUtf8("%1 mục").arg(visible));
    });
    connect(search_box, &QLineEdit::textChanged, page, [upd] { upd->start(200); });
    connect(quarantine_table_->model(), &QAbstractItemModel::rowsInserted, page, [upd] { upd->start(); });
    connect(quarantine_table_->model(), &QAbstractItemModel::rowsRemoved, page, [upd] { upd->start(); });
    upd->start();

    connect(quarantine_table_->selectionModel(), &QItemSelectionModel::selectionChanged, page,
            [this, batch_bar, sel_lbl] {
        const int n = quarantine_table_->selectionModel()->selectedRows().count();
        sel_lbl->setText(QString::fromUtf8("%1 mục đã chọn").arg(n));
        batch_bar->setVisible(n > 0);
    });

    connect(export_btn, &QPushButton::clicked, this, [this] {
        const QString path = QFileDialog::getSaveFileName(
            this, QString::fromUtf8("Export quarantine list"),
            "quarantine.csv", "CSV (*.csv)");
        if (path.isEmpty()) return;
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(this, QString::fromUtf8("Export thất bại"),
                                 QString::fromUtf8("Không ghi được file: %1").arg(path));
            return;
        }
        QTextStream ts(&f);
        ts << "id,file,rule,quarantined_at,original_path\n";
        for (int r = 0; r < quarantine_table_->rowCount(); ++r) {
            if (!quarantine_table_->item(r, 0) || quarantine_table_->isRowHidden(r)) continue;
            auto cell = [this, r](int c) {
                auto* it = quarantine_table_->item(r, c);
                QString s = it ? it->text() : QString();
                s.replace('"', '\'');
                return s;
            };
            ts << cell(0) << ",\"" << cell(1) << "\",\"" << cell(2) << "\",\""
               << cell(3) << "\",\"" << cell(4) << "\"\n";
        }
    });

    return page;
}

// BuildSettingsPage() moved to main_window_settings.cpp

QWidget* MainWindow::BuildHashListPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(28, 28, 28, 28);
    layout->setSpacing(12);

    auto* heading = new QLabel(QString::fromUtf8("Whitelist / Blacklist Hash"), page);
    heading->setStyleSheet("font-size: 16pt; font-weight: 700; color: #ffffff; background: transparent;");
    layout->addWidget(heading);

    auto* tabs = new QTabWidget(page);

    auto MakeHashTab = [&](bool is_whitelist) -> QWidget* {
        auto* tab = new QWidget();
        auto* tab_layout = new QVBoxLayout(tab);
        tab_layout->setContentsMargins(12, 12, 12, 12);
        tab_layout->setSpacing(8);

        auto* btn_row = new QHBoxLayout();
        btn_row->setSpacing(8);
        auto* add_btn = new QPushButton(QString::fromUtf8("+ Thêm hash"), tab);
        auto* remove_btn = new QPushButton(QString::fromUtf8("− Xóa"), tab);
        remove_btn->setObjectName("DangerButton");
        btn_row->addWidget(add_btn);
        btn_row->addWidget(remove_btn);
        btn_row->addStretch();
        tab_layout->addLayout(btn_row);

        auto* table = new QTableWidget(0, 2, tab);
        table->setHorizontalHeaderLabels({"SHA-256", QString::fromUtf8("Ghi chú")});
        table->horizontalHeader()->setStretchLastSection(true);
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->setVisible(false);
        tab_layout->addWidget(table);

        if (is_whitelist) whitelist_table_ = table;
        else blacklist_table_ = table;

        connect(add_btn, &QPushButton::clicked, this,
                [this, table, is_whitelist] { OnAddHashClicked(table, is_whitelist); });
        connect(remove_btn, &QPushButton::clicked, this,
                [this, table, is_whitelist] { OnRemoveHashClicked(table, is_whitelist); });

        return tab;
    };

    tabs->addTab(MakeHashTab(true), QString::fromUtf8("Whitelist (tin cậy)"));
    tabs->addTab(MakeHashTab(false), QString::fromUtf8("Blacklist (chặn)"));
    layout->addWidget(tabs);

    return page;
}

void MainWindow::GoToPage(int index) {
    const int previous = pages_->currentIndex();
    pages_->setCurrentIndex(index);
    // Figma-style page transition: slide in from the right (24px) + fade.
    // A pure opacity fade on a full page is nearly invisible; the horizontal
    // motion is what makes the switch feel alive.
    // On low-end/old hardware skip the slide+fade entirely: the page is already
    // shown (setCurrentIndex above), and the per-frame QGraphicsOpacityEffect on
    // a full page is exactly the kind of raster effect that janks weak machines.
    if (QWidget* incoming = pages_->currentWidget();
        incoming && previous != index && !IsLowEndSystem()) {
        const QPoint home = incoming->pos();
        incoming->move(home + QPoint(24, 0));
        auto* slide = new QPropertyAnimation(incoming, "pos", incoming);
        slide->setDuration(280);
        slide->setStartValue(home + QPoint(24, 0));
        slide->setEndValue(home);
        slide->setEasingCurve(QEasingCurve::OutCubic);
        slide->start(QAbstractAnimation::DeleteWhenStopped);

        auto* eff = new QGraphicsOpacityEffect(incoming);
        eff->setOpacity(0.0);
        incoming->setGraphicsEffect(eff);
        auto* anim = new QPropertyAnimation(eff, "opacity", incoming);
        anim->setDuration(250);
        anim->setStartValue(0.0);
        anim->setEndValue(1.0);
        anim->setEasingCurve(QEasingCurve::OutCubic);
        connect(anim, &QPropertyAnimation::finished, incoming, [incoming] {
            incoming->setGraphicsEffect(nullptr);
        });
        anim->start(QAbstractAnimation::DeleteWhenStopped);
    }
    if (auto* button = nav_group_->button(index)) {
        button->setChecked(true);
        // Brief opacity pulse on nav selection — decorative only; skip on low-end.
        if (!IsLowEndSystem()) {
            auto* eff = new QGraphicsOpacityEffect(button);
            eff->setOpacity(1.0);
            button->setGraphicsEffect(eff);
            auto* pa = new QPropertyAnimation(eff, "opacity", button);
            pa->setDuration(350);
            pa->setKeyValueAt(0.0, 1.0);
            pa->setKeyValueAt(0.25, 0.55);
            pa->setKeyValueAt(1.0, 1.0);
            pa->setEasingCurve(QEasingCurve::InOutCubic);
            connect(pa, &QPropertyAnimation::finished, button, [button] {
                button->setGraphicsEffect(nullptr);
            });
            pa->start(QAbstractAnimation::DeleteWhenStopped);
        }
    }
    if (index == 1 && nav_history_btn_) {
        detection_unread_ = 0;
        static_cast<BadgeButton*>(nav_history_btn_)->setBadge(0);
    }
    if (index == 0) {
        RefreshHomeStats();
        if (detection_chart_) detection_chart_->setData(engine_->RecentDetections(1000));
    }
    if (index == 2) ReloadQuarantineTable();
    if (index == 4) {
        ReloadHashTable(whitelist_table_, true);
        ReloadHashTable(blacklist_table_, false);
    }
}

void MainWindow::LoadHistory() {
    const auto history = engine_->RecentDetections(200);
    for (auto it = history.rbegin(); it != history.rend(); ++it) {
        AppendDetectionRow(*it);
    }
}

void MainWindow::AppendDetectionRow(const avcore::DetectionEvent& event) {
    const int row = detections_table_->rowCount();
    detections_table_->insertRow(row);
    detections_table_->setItem(row, 0, new QTableWidgetItem(TimePointToQString(event.timestamp)));

    auto* severity_item = new QTableWidgetItem(SeverityToQString(event.severity));
    QFont bold_font = severity_item->font();
    bold_font.setBold(true);
    severity_item->setFont(bold_font);
    severity_item->setForeground(SeverityColor(event.severity));
    detections_table_->setItem(row, 1, severity_item);

    detections_table_->setItem(row, 2, new QTableWidgetItem(QString::fromUtf8(event.rule_id.c_str())));
    {
        const QString full_path = QString::fromUtf8(event.target_path.c_str());
        auto* path_item = new QTableWidgetItem(full_path);
        path_item->setToolTip(full_path);
        detections_table_->setItem(row, 3, path_item);
    }
    detections_table_->setItem(row, 4, new QTableWidgetItem(QString::fromUtf8(event.evidence.c_str())));
    detections_table_->scrollToBottom();

    if (event.severity == avcore::Severity::Malicious) {
        ShowThreatNotification(event);
        // Badge the History nav entry when user is on a different page
        if (pages_->currentIndex() != 1 && nav_history_btn_) {
            ++detection_unread_;
            static_cast<BadgeButton*>(nav_history_btn_)->setBadge(detection_unread_);
        }
    }

    if (event.rule_id == "SYS.QUARANTINED") ReloadQuarantineTable();
    if (pages_->currentIndex() == 0) RefreshHomeStats();

    // Update protection component status indicators
    auto setStatus = [](QLabel* lbl, bool ok, const QString& name, const QString& detail = {}) {
        if (!lbl) return;
        const QString text = ok
            ? QString::fromUtf8("● %1  %2").arg(name, detail.isEmpty() ? QString::fromUtf8("Hoạt động") : detail)
            : QString::fromUtf8("● %1  %2").arg(name, detail.isEmpty() ? QString::fromUtf8("Không hoạt động") : detail);
        lbl->setText(text);
        lbl->setStyleSheet(ok ? "color: #4ADE80; font-weight: 600;"
                              : "color: #FF5A6A; font-weight: 600;");
        lbl->setProperty("statusSet", true);
    };

    if (event.rule_id == "SYS.REALTIME_STARTED") {
        folder_watch_ok_ = true;
        setStatus(folder_watch_status_, true, QString::fromUtf8("Folder Watch"));
    } else if (event.rule_id == "SYS.ETW_START_FAILED") {
        etw_ok_ = false;
        setStatus(etw_monitor_status_, false, QString::fromUtf8("ETW Monitor"),
                  QString::fromUtf8("Cần Admin"));
    } else if (event.rule_id == "SYS.MINIFILTER_CONNECTED") {
        driver_ok_ = true;
        setStatus(driver_status_, true, QString::fromUtf8("Driver Block"));
    } else if (event.rule_id == "SYS.MINIFILTER_CONNECT_FAILED") {
        driver_ok_ = false;
        setStatus(driver_status_, false, QString::fromUtf8("Driver Block"),
                  QString::fromUtf8("Không tải"));
    }

    // Any posture change may move the Security Score / shields count, and the
    // Home page may be visible -- refresh it so the ring never lies.
    if (event.rule_id.rfind("SYS.", 0) == 0 && pages_->currentIndex() == 0)
        RefreshHomeStats();
}

void MainWindow::ReloadQuarantineTable() {
    quarantine_table_->clearSpans();
    quarantine_table_->setRowCount(0);
    for (const auto& record : engine_->ListQuarantine()) {
        const int row = quarantine_table_->rowCount();
        quarantine_table_->insertRow(row);
        const QString path = QString::fromUtf8(record.original_path.c_str());
        auto colored = [](const QString& s, const char* hex) {
            auto* it = new QTableWidgetItem(s);
            it->setForeground(QColor(hex));
            return it;
        };
        quarantine_table_->setItem(row, 0, new QTableWidgetItem(QString::number(record.id)));
        auto* name_item = colored(QFileInfo(path).fileName(), theme::Text);
        name_item->setToolTip(path);
        quarantine_table_->setItem(row, 1, name_item);
        quarantine_table_->setItem(row, 2, colored(QString::fromUtf8(record.rule_id.c_str()), theme::AccentSoft));
        quarantine_table_->setItem(row, 3, colored(TimePointToQString(record.quarantined_at), theme::Dim));
        auto* path_item = colored(path, theme::Dim);
        path_item->setToolTip(path);  // hover shows the full, un-elided path
        quarantine_table_->setItem(row, 4, path_item);
    }
    if (quarantine_table_->rowCount() == 0) {
        // Empty state: one non-selectable spanning row (no ID cell in col 0, which
        // is how the filter/count pass and the action slots recognize it).
        quarantine_table_->insertRow(0);
        quarantine_table_->setSpan(0, 1, 1, 4);
        auto* msg = new QTableWidgetItem(
            QString::fromUtf8("Không có mục cách ly nào — tệp bị chặn sẽ xuất hiện ở đây"));
        msg->setForeground(QColor(theme::Dim));
        msg->setTextAlignment(Qt::AlignCenter);
        msg->setFlags(Qt::ItemIsEnabled);
        quarantine_table_->setItem(0, 1, msg);
    }
}

void MainWindow::RefreshHomeStats() {
    const auto stats = engine_->GetStats();
    // Tick the stat tiles from their previous value instead of snapping, so
    // repeat visits to Home (and post-scan refreshes) read as live updates.
    static double prev_scans = 0, prev_detections = 0, prev_malicious = 0, prev_quarantine = 0;
    AnimateCounter(stat_scans_label_, prev_scans, stats.total_scans);
    AnimateCounter(stat_detections_label_, prev_detections, stats.total_detections);
    AnimateCounter(stat_malicious_label_, prev_malicious, stats.malicious_detections);
    AnimateCounter(stat_quarantine_label_, prev_quarantine, stats.active_quarantine_count);
    prev_scans = stats.total_scans;
    prev_detections = stats.total_detections;
    prev_malicious = stats.malicious_detections;
    prev_quarantine = stats.active_quarantine_count;

    const bool threat_active = stats.active_quarantine_count > 0;
    if (threat_active) {
        protection_status_label_->setText(
            QString::fromUtf8("Đã phát hiện và cách ly %1 mối nguy hiểm").arg(stats.active_quarantine_count));
        protection_status_label_->setStyleSheet("font-size: 22pt; font-weight: 800; color: #FF5A6A; background: transparent;");
    } else {
        protection_status_label_->setText(QString::fromUtf8("Máy của bạn đang được bảo vệ"));
        protection_status_label_->setStyleSheet("font-size: 22pt; font-weight: 800; color: #4ADE80; background: transparent;");
    }

    if (shield_widget_)
        static_cast<ShieldIconWidget*>(shield_widget_)->setThreat(threat_active);

    if (tray_icon_) {
        tray_icon_->setIcon(MakeTrayIcon(threat_active));
        tray_icon_->setToolTip(threat_active
                                    ? QString::fromUtf8("TeoAvSuite - %1 mối nguy hiểm").arg(stats.active_quarantine_count)
                                    : QString::fromUtf8("TeoAvSuite - Đang bảo vệ"));
    }

    // ── Real Security Score (replaces the old hardcoded 97) ──────────────────
    // Five protection layers: Hash + YARA are always-on scan layers; ETW,
    // Folder Watch and the kernel Driver Block are the failable ones tracked in
    // the posture booleans. Score = full coverage minus a penalty for each
    // missing layer, minus threat pressure from currently-quarantined items.
    const int active_layers = 2 // Hash + YARA always active
                            + (etw_ok_          ? 1 : 0)
                            + (folder_watch_ok_ ? 1 : 0)
                            + (driver_ok_       ? 1 : 0);
    const int missing_layers  = 5 - active_layers;
    const int threat_penalty  = std::min<int>(static_cast<int>(stats.active_quarantine_count) * 5, 30);
    int score = 100 - missing_layers * 12 - threat_penalty;
    score = std::clamp(score, 5, 100);
    if (score_ring_)
        static_cast<ScoreRingWidget*>(score_ring_)->setScore(score);

    if (shields_sub_label_) {
        shields_sub_label_->setText(
            QString::fromUtf8("%1/5 shields active · Hash · YARA · ETW behavior")
                .arg(active_layers));
    }

    RefreshHomeDetections();
}

void MainWindow::RefreshHomeDetections() {
    if (!home_detections_layout_) return;

    // Clear all existing detection cards
    while (QLayoutItem* item = home_detections_layout_->takeAt(0)) {
        if (item->widget()) item->widget()->deleteLater();
        delete item;
    }

    const auto recent = engine_->RecentDetections(5);
    if (recent.empty()) {
        auto* ph = new QLabel(QString::fromUtf8("Chưa có phát hiện nào"),
                              home_detections_layout_->parentWidget());
        ph->setStyleSheet("font-size: 8.5pt; color: #6B5444; background: transparent;");
        ph->setAlignment(Qt::AlignCenter);
        home_detections_layout_->addWidget(ph);
        return;
    }

    const auto now = std::chrono::system_clock::now();
    QVector<QWidget*> reveal_cards;
    for (auto it = recent.rbegin(); it != recent.rend(); ++it) {
        const auto& ev = *it;

        auto* card = new QFrame(home_detections_layout_->parentWidget());
        card->setStyleSheet(
            "QFrame { background: #2E1D10; border: 1px solid rgba(255,170,90,0.08); "
            "border-radius: 10px; }");
        auto* cl = new QVBoxLayout(card);
        cl->setContentsMargins(10, 8, 10, 8);
        cl->setSpacing(4);

        // Top row: name + severity badge
        auto* top = new QHBoxLayout();
        top->setSpacing(6);
        auto* name_lbl = new QLabel(QString::fromUtf8(ev.rule_id.c_str()), card);
        name_lbl->setStyleSheet(
            "font-size: 8pt; font-weight: 600; color: #ffffff; background: transparent;");
        top->addWidget(name_lbl, 1);

        // Severity badge chip (matches Figma SeverityBadge)
        struct BadgeStyle { QString bg; QString fg; QString text; };
        BadgeStyle bs;
        switch (ev.severity) {
            case avcore::Severity::Malicious:
                bs = {"rgba(255,90,106,0.15)", "#FF5A6A", "Critical"}; break;
            case avcore::Severity::Suspicious:
                bs = {"rgba(251,191,36,0.15)", "#FBBF24", "Medium"}; break;
            default:
                bs = {"rgba(74,222,128,0.12)", "#4ADE80", "Low"}; break;
        }
        auto* badge = new QLabel(bs.text, card);
        badge->setStyleSheet(
            QString("font-size: 7.5pt; font-weight: 500; padding: 2px 7px; border-radius: 10px; "
                    "background: %1; color: %2;").arg(bs.bg, bs.fg));
        top->addWidget(badge);
        cl->addLayout(top);

        // Path (truncated)
        const QString path = QString::fromUtf8(ev.target_path.c_str());
        auto* path_lbl = new QLabel(path, card);
        path_lbl->setStyleSheet("font-size: 7pt; color: #6B5444; background: transparent;");
        path_lbl->setToolTip(path);
        cl->addWidget(path_lbl);

        // Bottom row: time + action
        auto* bot = new QHBoxLayout();
        const auto age_s = std::chrono::duration_cast<std::chrono::seconds>(
            now - ev.timestamp).count();
        const QString age = age_s < 60 ? QString::fromUtf8("%1s trước").arg(age_s)
                          : age_s < 3600 ? QString::fromUtf8("%1m trước").arg(age_s / 60)
                          : QString::fromUtf8("%1h trước").arg(age_s / 3600);
        auto* time_lbl = new QLabel(age, card);
        time_lbl->setStyleSheet("font-size: 7pt; color: #6B5444; background: transparent;");
        bot->addWidget(time_lbl);
        bot->addStretch();
        const QString action = ev.severity == avcore::Severity::Malicious
                             ? "Quarantined" : "Blocked";
        auto* act_lbl = new QLabel(action, card);
        act_lbl->setStyleSheet("font-size: 7pt; font-weight: 500; color: #C7B6A2; background: transparent;");
        bot->addWidget(act_lbl);
        cl->addLayout(bot);

        home_detections_layout_->addWidget(card);
        reveal_cards.push_back(card);
    }
    StaggerReveal(reveal_cards);
}

std::int64_t MainWindow::SelectedQuarantineId() const {
    const auto selected = quarantine_table_->selectionModel()->selectedRows();
    if (selected.isEmpty()) return 0;
    auto* id_item = quarantine_table_->item(selected.first().row(), 0);
    return id_item ? id_item->text().toLongLong() : 0;  // empty-state row has no ID cell
}

void MainWindow::RunScanInBackground(std::function<void()> work) {
    scan_folder_button_->setEnabled(false);
    scan_files_button_->setEnabled(false);
    scan_registry_button_->setEnabled(false);
    scan_memory_button_->setEnabled(false);
    scan_persistence_button_->setEnabled(false);
    cancel_scan_button_->setEnabled(true);
    cancel_scan_button_->setVisible(true);
    status_label_->setText(QString::fromUtf8("Đang quét..."));

    std::thread([this, work = std::move(work)] {
        work();
        QMetaObject::invokeMethod(
            this,
            [this] {
                scan_folder_button_->setEnabled(true);
                scan_files_button_->setEnabled(true);
                scan_registry_button_->setEnabled(true);
                scan_memory_button_->setEnabled(true);
                scan_persistence_button_->setEnabled(true);
                cancel_scan_button_->setEnabled(true);
                cancel_scan_button_->setVisible(false);
                scan_progress_->setVisible(false);
                scan_files_label_->setVisible(false);
                if (status_label_->text() == QString::fromUtf8("Đang hủy..."))
                    status_label_->setText(QString::fromUtf8("Đã hủy."));
                RefreshHomeStats();
                if (detection_chart_) detection_chart_->setData(engine_->RecentDetections(1000));
            },
            Qt::QueuedConnection);
    }).detach();
}

void MainWindow::OnScanFolderClicked() {
    QFileDialog dialog(this, QString::fromUtf8("Chọn thư mục hoặc ổ đĩa để quét"));
    dialog.setFileMode(QFileDialog::Directory);
    dialog.setOption(QFileDialog::DontResolveSymlinks, true);
    dialog.setOption(QFileDialog::DontUseNativeDialog, true);
    // ShowDirsOnly conflicts with HiddenFilesShown on non-native dialog — use explicit filter instead
    dialog.setFilter(QDir::AllDirs | QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden);
    if (dialog.exec() != QDialog::Accepted) return;
    const QString dir = dialog.selectedFiles().value(0);
    if (dir.isEmpty()) return;

    // Progress bar stays indeterminate (range 0,0) until scan finishes —
    // streaming approach means total file count is unknown upfront.
    scan_progress_->setRange(0, 0);
    scan_progress_->setVisible(true);
    scan_files_label_->setText(QString::fromUtf8("Đang quét..."));
    scan_files_label_->setVisible(true);

    const std::string dir_std = dir.toStdString();
    const int detections_before = static_cast<int>(engine_->RecentDetections(10000).size());

    RunScanInBackground([this, dir_std, detections_before] {
        int total_files = 0;
        engine_->ScanDirectory(dir_std, [this, &total_files](int current, int total) {
            total_files = (total > 0) ? total : current;
            QMetaObject::invokeMethod(this, [this, current, total] {
                if (total > 0) {
                    scan_progress_->setRange(0, 0); // keep indeterminate
                }
                scan_files_label_->setText(
                    QString::fromUtf8("Đã quét %1 tệp...").arg(current));
            }, Qt::QueuedConnection);
        });

        const int new_detections =
            static_cast<int>(engine_->RecentDetections(10000).size()) - detections_before;
        QMetaObject::invokeMethod(this, [this, total_files, new_detections] {
            const QString summary = new_detections > 0
                ? QString::fromUtf8("Đã quét %1 tệp — phát hiện %2 mối đe dọa!")
                      .arg(total_files).arg(new_detections)
                : QString::fromUtf8("Đã quét %1 tệp — không phát hiện mối đe dọa.")
                      .arg(total_files);
            status_label_->setText(summary);
        }, Qt::QueuedConnection);
    });
}

void MainWindow::OnScanFilesClicked() {
    QFileDialog dialog(this, QString::fromUtf8("Chọn file để quét"));
    dialog.setFileMode(QFileDialog::ExistingFiles);
    dialog.setNameFilter(QString::fromUtf8("Tất cả file (*.*)"));
    dialog.setOption(QFileDialog::DontUseNativeDialog, true);
    if (dialog.exec() != QDialog::Accepted) return;
    const QStringList files = dialog.selectedFiles();
    if (files.isEmpty()) return;

    scan_progress_->setRange(0, files.size());
    scan_progress_->setValue(0);
    scan_progress_->setVisible(true);
    scan_files_label_->setText(QString::fromUtf8("0 / %1 file").arg(files.size()));
    scan_files_label_->setVisible(true);

    const int detections_before = static_cast<int>(engine_->RecentDetections(10000).size());

    // Convert to std::vector<std::string> before moving to background thread
    std::vector<std::string> paths;
    paths.reserve(static_cast<size_t>(files.size()));
    for (const auto& f : files) paths.push_back(f.toStdString());

    RunScanInBackground([this, paths = std::move(paths), detections_before] {
        const int total = static_cast<int>(paths.size());
        for (int i = 0; i < total; ++i) {
            engine_->ScanFile(paths[static_cast<size_t>(i)]);
            const int done = i + 1;
            QMetaObject::invokeMethod(this, [this, done, total] {
                scan_progress_->setValue(done);
                scan_files_label_->setText(
                    QString::fromUtf8("%1 / %2 file").arg(done).arg(total));
            }, Qt::QueuedConnection);
        }
        const int new_det =
            static_cast<int>(engine_->RecentDetections(10000).size()) - detections_before;
        QMetaObject::invokeMethod(this, [this, total, new_det] {
            status_label_->setText(new_det > 0
                ? QString::fromUtf8("Đã quét %1 file — phát hiện %2 mối đe dọa!").arg(total).arg(new_det)
                : QString::fromUtf8("Đã quét %1 file — không phát hiện mối đe dọa.").arg(total));
        }, Qt::QueuedConnection);
    });
}

void MainWindow::OnScanRegistryClicked() {
    RunScanInBackground([this] { engine_->ScanRegistry(); });
}

void MainWindow::OnScanMemoryClicked() {
    scan_progress_->setRange(0, 0); // indeterminate while enumerating
    scan_progress_->setVisible(true);
    scan_files_label_->setText(QString::fromUtf8("Đang quét bộ nhớ tiến trình..."));
    scan_files_label_->setVisible(true);

    RunScanInBackground([this] {
        int total_processes = 0;
        const int detections = engine_->ScanAllProcesses(
            [this, &total_processes](int current, int total) {
                total_processes = total;
                QMetaObject::invokeMethod(this, [this, current, total] {
                    scan_progress_->setRange(0, total);
                    scan_progress_->setValue(current);
                    scan_files_label_->setText(
                        QString::fromUtf8("Tiến trình %1 / %2").arg(current).arg(total));
                }, Qt::QueuedConnection);
            });

        QMetaObject::invokeMethod(this, [this, detections, total_processes] {
            status_label_->setText(
                detections > 0
                    ? QString::fromUtf8("Quét bộ nhớ: phát hiện %1 mối đe dọa trong %2 tiến trình!")
                          .arg(detections).arg(total_processes)
                    : QString::fromUtf8("Quét bộ nhớ: sạch (%1 tiến trình).").arg(total_processes));
        }, Qt::QueuedConnection);
    });
}

void MainWindow::OnClearHistoryClicked() {
    const auto answer = QMessageBox::question(this, QString::fromUtf8("Xóa lịch sử"),
                                               QString::fromUtf8("Xóa toàn bộ lịch sử quét? Không thể hoàn tác."));
    if (answer != QMessageBox::Yes) return;
    engine_->ClearHistory();
    detections_table_->setRowCount(0);
    status_label_->setText(QString::fromUtf8("Đã xóa lịch sử."));
    RefreshHomeStats();
}

void MainWindow::OnExportDetectionsClicked() {
    const QString save_path = QFileDialog::getSaveFileName(
        this,
        QString::fromUtf8("Xuất báo cáo phát hiện"),
        "avsuite_report",
        QString::fromUtf8("JSON (*.json);;CSV (*.csv)"));
    if (save_path.isEmpty()) return;

    const auto events = engine_->RecentDetections(100000);

    QFile file(save_path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, QString::fromUtf8("Export thất bại"),
                             QString::fromUtf8("Không thể tạo file:\n") + save_path);
        return;
    }

    QTextStream out(&file);
    out.setEncoding(QStringConverter::Utf8);

    const bool is_csv = save_path.endsWith(".csv", Qt::CaseInsensitive);
    if (is_csv) {
        out << "Timestamp,Severity,Rule,Path,Evidence\n";
        for (const auto& ev : events) {
            auto esc = [](const QString& s) {
                return "\"" + QString(s).replace("\"", "\"\"") + "\"";
            };
            out << esc(TimePointToQString(ev.timestamp)) << ","
                << esc(SeverityToQString(ev.severity)) << ","
                << esc(QString::fromUtf8(ev.rule_id.c_str())) << ","
                << esc(QString::fromUtf8(ev.target_path.c_str())) << ","
                << esc(QString::fromUtf8(ev.evidence.c_str())) << "\n";
        }
    } else {
        QJsonArray arr;
        for (const auto& ev : events) {
            QJsonObject obj;
            obj["timestamp"] = TimePointToQString(ev.timestamp);
            obj["severity"]  = SeverityToQString(ev.severity);
            obj["rule"]      = QString::fromUtf8(ev.rule_id.c_str());
            obj["path"]      = QString::fromUtf8(ev.target_path.c_str());
            obj["evidence"]  = QString::fromUtf8(ev.evidence.c_str());
            arr.append(obj);
        }
        out << QJsonDocument(arr).toJson(QJsonDocument::Indented);
    }

    status_label_->setText(
        QString::fromUtf8("Đã xuất %1 bản ghi ra %2")
            .arg(static_cast<int>(events.size()))
            .arg(QFileInfo(save_path).fileName()));
}

void MainWindow::OnExportListsClicked() {
    const QString path = QFileDialog::getSaveFileName(this, QString::fromUtf8("Export blacklist/whitelist"),
                                                       "avsuite_lists.json", "JSON (*.json)");
    if (path.isEmpty()) return;
    const auto result = engine_->ExportHashLists(path.toStdString());
    if (!result.success) {
        QMessageBox::warning(this, QString::fromUtf8("Export thất bại"), QString::fromUtf8(result.error.c_str()));
        return;
    }
    status_label_->setText(QString::fromUtf8("Đã export %1 whitelist + %2 blacklist.")
                                .arg(result.whitelist_count)
                                .arg(result.blacklist_count));
}

void MainWindow::OnImportListsClicked() {
    const QString path =
        QFileDialog::getOpenFileName(this, QString::fromUtf8("Import blacklist/whitelist"), QString(), "JSON (*.json)");
    if (path.isEmpty()) return;
    const auto result = engine_->ImportHashLists(path.toStdString());
    if (!result.success) {
        QMessageBox::warning(this, QString::fromUtf8("Import thất bại"), QString::fromUtf8(result.error.c_str()));
        return;
    }
    status_label_->setText(QString::fromUtf8("Đã import %1 whitelist + %2 blacklist.")
                                .arg(result.whitelist_count)
                                .arg(result.blacklist_count));
}

void MainWindow::OnSelectAllQuarantineClicked() {
    quarantine_table_->selectAll();
}

void MainWindow::OnRestoreQuarantineClicked() {
    const auto selected = quarantine_table_->selectionModel()->selectedRows();
    if (selected.isEmpty()) return;
    int restored_count = 0;
    for (const auto& idx : selected) {
        auto* id_item = quarantine_table_->item(idx.row(), 0);
        if (!id_item) continue;  // empty-state row
        const std::int64_t id = id_item->text().toLongLong();
        if (engine_->RestoreFromQuarantine(id)) {
            ++restored_count;
        }
    }
    if (restored_count == 0) {
        QMessageBox::warning(this, QString::fromUtf8("Restore thất bại"),
                              QString::fromUtf8("Không thể restore (đã restore trước đó, file gốc đã có lại, "
                                                 "hoặc file quarantine bị mất)."));
        return;
    }
    if (restored_count < selected.count()) {
        QMessageBox::information(this, QString::fromUtf8("Restore một phần"),
                                 QString::fromUtf8("Restored %1 / %2 files.")
                                 .arg(restored_count).arg(selected.count()));
    }
    ReloadQuarantineTable();
    RefreshHomeStats();
}

void MainWindow::OnDeleteQuarantineClicked() {
    const auto selected = quarantine_table_->selectionModel()->selectedRows();
    if (selected.isEmpty()) return;
    const auto answer = QMessageBox::question(
        this, QString::fromUtf8("Xóa vĩnh viễn"),
        QString::fromUtf8("Xóa vĩnh viễn %1 file(s) khỏi quarantine? Không thể hoàn tác.")
        .arg(selected.count()));
    if (answer != QMessageBox::Yes) return;
    int deleted_count = 0;
    for (const auto& idx : selected) {
        auto* id_item = quarantine_table_->item(idx.row(), 0);
        if (!id_item) continue;  // empty-state row
        const std::int64_t id = id_item->text().toLongLong();
        if (engine_->DeleteQuarantine(id)) {
            ++deleted_count;
        }
    }
    if (deleted_count == 0) {
        QMessageBox::warning(this, QString::fromUtf8("Xóa thất bại"), QString::fromUtf8("Không thể xóa bất kỳ entry nào."));
        return;
    }
    if (deleted_count < selected.count()) {
        QMessageBox::information(this, QString::fromUtf8("Xóa một phần"),
                                 QString::fromUtf8("Deleted %1 / %2 files.")
                                 .arg(deleted_count).arg(selected.count()));
    }
    ReloadQuarantineTable();
    RefreshHomeStats();
}

// --- Settings page ---

void MainWindow::OnAddWatchDirClicked() {
    const QString dir = QFileDialog::getExistingDirectory(
        this, QString::fromUtf8("Chọn thư mục theo dõi"),
        QString(), QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (dir.isEmpty()) return;
    // Avoid adding the same directory twice.
    for (int i = 0; i < watch_dir_list_->count(); ++i) {
        if (watch_dir_list_->item(i)->text() == dir) return;
    }
    watch_dir_list_->addItem(dir);
}

void MainWindow::OnRemoveWatchDirClicked() {
    const auto selected = watch_dir_list_->selectedItems();
    if (selected.isEmpty()) return;
    delete selected.first();
}

void MainWindow::OnSaveSettingsClicked() {
    config_.watch_directories.clear();
    for (int i = 0; i < watch_dir_list_->count(); ++i) {
        config_.watch_directories.push_back(watch_dir_list_->item(i)->text().toStdString());
    }
    config_.debounce_ms = debounce_spin_->value();
    config_.scheduled_scan.enabled = schedule_enabled_check_->isChecked();
    config_.scheduled_scan.interval = schedule_interval_combo_->currentData().toString().toStdString();
    config_.scheduled_scan.time_hhmm = schedule_time_edit_->text().toStdString();
    config_.scheduled_scan.target_path = schedule_path_edit_->text().toStdString();
    if (vt_key_edit_) config_.virustotal_api_key = vt_key_edit_->text().toStdString();
    if (mb_key_edit_) config_.malwarebazaar_api_key = mb_key_edit_->text().toStdString();
    if (ai_model_path_edit_) config_.ai_model_path = ai_model_path_edit_->text().toStdString();

    if (config_.config_file_path.empty() || !config_.SaveToFile(config_.config_file_path)) {
        QMessageBox::warning(this, QString::fromUtf8("Lỗi"),
                              QString::fromUtf8("Không thể lưu cấu hình.\n"
                                                 "(config_file_path trống hoặc không ghi được file)"));
        return;
    }

    engine_->SetScheduledScan(config_.scheduled_scan);

    QMessageBox::information(
        this, QString::fromUtf8("Đã lưu"),
        QString::fromUtf8("Cấu hình đã được lưu.\n"
                           "Lịch quét tự động đã được áp dụng ngay lập tức.\n"
                           "Thay đổi Watch Directories sẽ có hiệu lực khi khởi động lại ứng dụng."));
}

// --- Hash list page ---

void MainWindow::ReloadHashTable(QTableWidget* table, bool is_whitelist) {
    table->setRowCount(0);
    const auto entries = is_whitelist ? engine_->ListWhitelistHashes() : engine_->ListBlacklistHashes();
    for (const auto& entry : entries) {
        const int row = table->rowCount();
        table->insertRow(row);
        table->setItem(row, 0, new QTableWidgetItem(QString::fromUtf8(entry.sha256.c_str())));
        table->setItem(row, 1, new QTableWidgetItem(QString::fromUtf8(entry.note.c_str())));
    }
}

int MainWindow::ImportThreatIntelHashes(const std::vector<std::pair<std::string, std::string>>& sha256_and_note) {
    std::unordered_set<std::string> existing;
    for (const auto& e : engine_->ListBlacklistHashes()) existing.insert(e.sha256);

    int added = 0;
    for (const auto& [sha256, note] : sha256_and_note) {
        if (existing.count(sha256)) continue;
        engine_->AddToBlacklist(sha256, note);
        existing.insert(sha256);
        ++added;
    }
    if (added > 0 && blacklist_table_) ReloadHashTable(blacklist_table_, false);
    return added;
}

std::vector<avcore::DetectionEvent> MainWindow::GetRecentDetections(int limit) const {
    return engine_->RecentDetections(limit);
}

ThreatIntelUpdateResult MainWindow::FetchThreatIntelFeed() {
    ThreatIntelUpdateResult out;
    const auto fetch = engine_->FetchMalwareBazaarRecent();
    out.success = fetch.success;
    out.error = fetch.error;
    out.entries.reserve(fetch.entries.size());
    for (const auto& e : fetch.entries) {
        out.entries.emplace_back(e.sha256,
            "ThreatIntel: " + e.signature + " (first seen " + e.first_seen + ")");
    }
    return out;
}

QString MainWindow::LookupVtIoc(const QString& kind, const QString& value) {
    const std::string v = value.toStdString();
    std::string result;
    if (kind == "hash") result = engine_->LookupVirusTotal(v);
    else if (kind == "ip") result = engine_->LookupVirusTotalIp(v);
    else if (kind == "domain") result = engine_->LookupVirusTotalDomain(v);
    else result = "Không nhận diện được loại IOC.";
    return QString::fromStdString(result);
}

QString MainWindow::UpdateServerUrl() const {
    return QString::fromStdString(config_.update_server_url);
}

void MainWindow::OnAddHashClicked(QTableWidget* table, bool is_whitelist) {
    bool ok = false;
    const QString sha256 = QInputDialog::getText(
        this, QString::fromUtf8("Thêm hash"), "SHA-256:", QLineEdit::Normal, QString(), &ok);
    if (!ok || sha256.trimmed().isEmpty()) return;

    const QString note = QInputDialog::getText(
        this, QString::fromUtf8("Ghi chú"), QString::fromUtf8("Ghi chú (tùy chọn):"),
        QLineEdit::Normal, QString(), &ok);
    if (!ok) return;

    if (is_whitelist) engine_->AddToWhitelist(sha256.trimmed().toStdString(), note.toStdString());
    else engine_->AddToBlacklist(sha256.trimmed().toStdString(), note.toStdString());

    ReloadHashTable(table, is_whitelist);
}

void MainWindow::OnRemoveHashClicked(QTableWidget* table, bool is_whitelist) {
    const auto selected = table->selectionModel()->selectedRows();
    if (selected.isEmpty()) return;

    const std::string sha256 = table->item(selected.first().row(), 0)->text().toStdString();
    if (is_whitelist) engine_->RemoveFromWhitelist(sha256);
    else engine_->RemoveFromBlacklist(sha256);

    ReloadHashTable(table, is_whitelist);
}

// ─── ETW Monitor page ────────────────────────────────────────────────────────

QWidget* MainWindow::BuildEtwPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(28, 28, 28, 28);
    layout->setSpacing(12);

    auto* heading = new QLabel(QString::fromUtf8("ETW Process Monitor"), page);
    heading->setStyleSheet("font-size: 16pt; font-weight: 700; color: #ffffff; background: transparent;");
    layout->addWidget(heading);

    auto* desc = new QLabel(
        QString::fromUtf8("Live process creation events từ Microsoft-Windows-Kernel-Process ETW provider. "
                           "Yêu cầu chạy với quyền Administrator."), page);
    desc->setStyleSheet("color: rgba(255, 255, 255, 0.45); font-size: 9pt;");
    desc->setWordWrap(true);
    layout->addWidget(desc);

    auto* btn_row = new QHBoxLayout();
    auto* clear_btn = new QPushButton(QString::fromUtf8("   X\xc3\xb3" "a log"), page);
    clear_btn->setObjectName("DangerButton");
    {
        auto* ci = new IconWidget(IconWidget::Archive, 13, QColor(0xC7,0xB6,0xA2), clear_btn);
        ci->setAttribute(Qt::WA_TransparentForMouseEvents);
        ci->move(9, 8);
    }
    btn_row->addWidget(clear_btn);
    btn_row->addStretch();
    layout->addLayout(btn_row);

    etw_table_ = new QTableWidget(0, 5, page);
    etw_table_->setHorizontalHeaderLabels(
        {QString::fromUtf8("Thời gian"), "PID", "PPID",
         QString::fromUtf8("Image"), QString::fromUtf8("Command Line")});
    etw_table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    etw_table_->horizontalHeader()->setStretchLastSection(true);
    etw_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    etw_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    etw_table_->setAlternatingRowColors(true);
    etw_table_->verticalHeader()->setVisible(false);
    layout->addWidget(etw_table_);

    connect(clear_btn, &QPushButton::clicked, this, [this] { etw_table_->setRowCount(0); });

    return page;
}

// BuildAiPage is in main_window_ai.cpp
#if 0  // excluded — MakeBubble and BuildAiPage moved to main_window_ai.cpp
static QWidget* MakeBubble(const QString& text, Qt::Alignment align, QWidget* parent) {
    auto* row = new QWidget(parent);
    row->setStyleSheet("background: transparent;");
    auto* row_layout = new QHBoxLayout(row);
    row_layout->setContentsMargins(4, 3, 4, 3);
    row_layout->setSpacing(10);

    auto* bubble = new QFrame(row);
    bubble->setFrameShape(QFrame::NoFrame);
    bubble->setMaximumWidth(700);

    // Text label — objectName used by addBubble to retrieve it later
    auto* lbl = new QLabel(text, bubble);
    lbl->setObjectName("msg_text");
    lbl->setWordWrap(true);
    lbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lbl->setFont(QFont("Segoe UI", 10));

    auto* blayout = new QVBoxLayout(bubble);
    blayout->setContentsMargins(14, 10, 14, 10);
    blayout->addWidget(lbl);

    if (align == Qt::AlignRight) {
        // User bubble — rich blue gradient, right-aligned
        bubble->setStyleSheet(
            "QFrame {"
            " background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
            "  stop:0 #0553E8, stop:0.5 #0878FF, stop:1 #29A0FF);"
            " border-radius: 18px 18px 4px 18px;"
            " border: 1px solid rgba(41,160,255,0.4);"
            "}");
        lbl->setStyleSheet("color: #ffffff; font-size: 10pt; background: transparent;");
        row_layout->addStretch();
        row_layout->addWidget(bubble);
    } else {
        // AI bubble — glass-morphism dark card, left-aligned
        bubble->setStyleSheet(
            "QFrame {"
            " background: qlineargradient(x1:0,y1:0,x2:0,y2:1,"
            "  stop:0 rgba(10,30,50,0.97), stop:1 rgba(3,16,28,0.97));"
            " border: 1px solid rgba(7,135,255,0.22);"
            " border-left: 3px solid #0787FF;"
            " border-radius: 4px 18px 18px 18px;"
            "}");
        lbl->setStyleSheet("color: #d6eeff; font-size: 10pt; background: transparent;");

        // Avatar circle
        auto* avatar = new QLabel(QString::fromUtf8("🤖"), row);
        avatar->setObjectName("avatar");
        avatar->setFixedSize(34, 34);
        avatar->setAlignment(Qt::AlignCenter);
        avatar->setStyleSheet(
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
            " stop:0 rgba(7,100,220,0.35), stop:1 rgba(7,135,255,0.15));"
            " border: 1px solid rgba(7,135,255,0.3);"
            " border-radius: 17px; font-size: 15pt;");
        row_layout->addWidget(avatar, 0, Qt::AlignTop);
        row_layout->addWidget(bubble, 1);
        row_layout->addStretch();
    }

    return row;
}

QWidget* MainWindow::BuildAiPage() {
    auto* page = new QWidget();
    // Deep space gradient background for the whole page
    page->setStyleSheet(
        "QWidget#ai_page {"
        " background: qlineargradient(x1:0,y1:0,x2:0.4,y2:1,"
        "  stop:0 #040d1a, stop:0.5 #030a14, stop:1 #020810);"
        "}");
    page->setObjectName("ai_page");

    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(24, 18, 24, 14);
    layout->setSpacing(10);

    // ── Header ──
    auto* hdr_frame = new QFrame(page);
    hdr_frame->setStyleSheet(
        "QFrame {"
        " background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "  stop:0 rgba(7,100,220,0.18), stop:0.5 rgba(7,135,255,0.08), stop:1 rgba(0,0,0,0));"
        " border: 1px solid rgba(7,135,255,0.18);"
        " border-radius: 10px;"
        "}");
    auto* hdr_layout = new QHBoxLayout(hdr_frame);
    hdr_layout->setContentsMargins(14, 10, 14, 10);

    auto* hdr_icon = new QLabel(QString::fromUtf8("🛡"), hdr_frame);
    hdr_icon->setStyleSheet("font-size: 18pt; background: transparent;");
    hdr_layout->addWidget(hdr_icon);

    auto* hdr_texts = new QVBoxLayout();
    hdr_texts->setSpacing(1);
    auto* heading = new QLabel(QString::fromUtf8("TeoAV Assistant"), hdr_frame);
    heading->setStyleSheet(
        "font-size: 14pt; font-weight: 800; color: #ffffff; background: transparent;"
        " letter-spacing: 0.5px;");
    auto* sub_heading = new QLabel(QString::fromUtf8("Trợ lý AI phân tích bảo mật · Local LLM · GPU/CPU tự động"), hdr_frame);
    sub_heading->setStyleSheet(
        "font-size: 8.5pt; color: rgba(7,135,255,0.75); background: transparent;");
    hdr_texts->addWidget(heading);
    hdr_texts->addWidget(sub_heading);
    hdr_layout->addLayout(hdr_texts);
    hdr_layout->addStretch();

    ai_status_label_ = new QLabel(QString::fromUtf8("● Chưa tải model"), hdr_frame);
    ai_status_label_->setStyleSheet(
        "color: rgba(255,255,255,0.35); font-size: 8.5pt; font-style: italic;"
        " background: transparent;");
    hdr_layout->addWidget(ai_status_label_);
    layout->addWidget(hdr_frame);

    // ── Model path bar ──
    auto* model_bar = new QFrame(page);
    model_bar->setStyleSheet(
        "QFrame { background: rgba(5,18,35,0.8);"
        " border: 1px solid rgba(7,135,255,0.15);"
        " border-radius: 8px; }");
    auto* model_row = new QHBoxLayout(model_bar);
    model_row->setContentsMargins(10, 6, 8, 6);
    model_row->setSpacing(6);

    auto* model_lbl = new QLabel(QString::fromUtf8("Model"), model_bar);
    model_lbl->setStyleSheet(
        "color: rgba(7,135,255,0.7); font-size: 8.5pt; font-weight: 600;"
        " background: transparent;");
    model_lbl->setFixedWidth(40);
    model_row->addWidget(model_lbl);

    // vertical separator
    auto* sep = new QFrame(model_bar);
    sep->setFrameShape(QFrame::VLine);
    sep->setStyleSheet("color: rgba(7,135,255,0.2); background: rgba(7,135,255,0.2);");
    sep->setFixedWidth(1);
    model_row->addWidget(sep);

    auto* inline_model_edit = new QLineEdit(model_bar);
    inline_model_edit->setPlaceholderText(
        QString::fromUtf8("D:\\models\\Qwen2.5-7B-Instruct-Q4_K_M.gguf"));
    inline_model_edit->setStyleSheet(
        "QLineEdit { background: transparent; border: none;"
        " padding: 2px 6px; color: rgba(255,255,255,0.75); font-size: 8.5pt; }"
        "QLineEdit:focus { color: #ffffff; }");
    if (!config_.ai_model_path.empty())
        inline_model_edit->setText(QString::fromUtf8(config_.ai_model_path.c_str()));
    model_row->addWidget(inline_model_edit, 1);

    auto* browse_btn = new QPushButton(QString::fromUtf8("📂"), model_bar);
    browse_btn->setFixedSize(30, 26);
    browse_btn->setStyleSheet(
        "QPushButton { background: rgba(7,135,255,0.12); border: 1px solid rgba(7,135,255,0.25);"
        " border-radius: 5px; font-size: 11pt; color: white; }"
        "QPushButton:hover { background: rgba(7,135,255,0.28); }");
    model_row->addWidget(browse_btn);

    auto* load_btn = new QPushButton(QString::fromUtf8("⚡  Tải model"), model_bar);
    load_btn->setFixedWidth(110);
    load_btn->setStyleSheet(
        "QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "  stop:0 #0553E8, stop:1 #0898FF);"
        " color: #fff; font-weight: 700; font-size: 9pt;"
        " border-radius: 6px; padding: 5px 10px;"
        " border: 1px solid rgba(41,160,255,0.3); }"
        "QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "  stop:0 #0443C8, stop:1 #0787FF); }"
        "QPushButton:disabled { background: rgba(255,255,255,0.07);"
        " color: rgba(255,255,255,0.2); border-color: transparent; }");
    model_row->addWidget(load_btn);
    layout->addWidget(model_bar);

    // ── Chat scroll area ──
    ai_chat_scroll_ = new QScrollArea(page);
    ai_chat_scroll_->setWidgetResizable(true);
    ai_chat_scroll_->setFrameShape(QFrame::NoFrame);
    ai_chat_scroll_->setStyleSheet(
        "QScrollArea {"
        " background: qlineargradient(x1:0,y1:0,x2:0,y2:1,"
        "  stop:0 rgba(4,14,28,0.9), stop:1 rgba(2,8,18,0.95));"
        " border: 1px solid rgba(7,135,255,0.12);"
        " border-radius: 12px;"
        "}"
        "QScrollBar:vertical { background: transparent; width: 4px; margin: 6px 2px; }"
        "QScrollBar::handle:vertical { background: rgba(7,135,255,0.35); border-radius: 2px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }");

    ai_chat_widget_ = new QWidget();
    ai_chat_widget_->setStyleSheet("background: transparent;");
    // Make viewport transparent too
    ai_chat_scroll_->viewport()->setStyleSheet("background: transparent;");

    ai_chat_layout_ = new QVBoxLayout(ai_chat_widget_);
    ai_chat_layout_->setContentsMargins(14, 16, 14, 16);
    ai_chat_layout_->setSpacing(10);
    ai_chat_layout_->addStretch();

    ai_chat_scroll_->setWidget(ai_chat_widget_);
    layout->addWidget(ai_chat_scroll_, 1);

    // ── Input area ──
    auto* input_card = new QFrame(page);
    input_card->setStyleSheet(
        "QFrame {"
        " background: qlineargradient(x1:0,y1:0,x2:0,y2:1,"
        "  stop:0 rgba(8,22,42,0.95), stop:1 rgba(4,12,26,0.95));"
        " border: 1px solid rgba(7,135,255,0.22);"
        " border-top: 1px solid rgba(7,135,255,0.35);"
        " border-radius: 12px;"
        "}");
    auto* input_card_layout = new QVBoxLayout(input_card);
    input_card_layout->setContentsMargins(12, 8, 12, 10);
    input_card_layout->setSpacing(7);

    // Action chips row
    auto* btn_row = new QHBoxLayout();
    btn_row->setSpacing(6);
    auto* inject_btn = new QPushButton(QString::fromUtf8("📎  Đính kèm phát hiện"), input_card);
    inject_btn->setStyleSheet(
        "QPushButton { background: rgba(7,135,255,0.10); color: rgba(7,200,255,0.8);"
        " border: 1px solid rgba(7,135,255,0.22); border-radius: 12px;"
        " padding: 3px 12px; font-size: 8.5pt; }"
        "QPushButton:hover { background: rgba(7,135,255,0.22); color: #7ee8ff; }");
    btn_row->addWidget(inject_btn);
    btn_row->addStretch();
    auto* clear_btn = new QPushButton(QString::fromUtf8("🗑  Xóa chat"), input_card);
    clear_btn->setStyleSheet(
        "QPushButton { background: rgba(235,59,90,0.08); color: rgba(235,100,130,0.7);"
        " border: 1px solid rgba(235,59,90,0.18); border-radius: 12px;"
        " padding: 3px 12px; font-size: 8.5pt; }"
        "QPushButton:hover { background: rgba(235,59,90,0.2); color: #ff6b8a; }");
    btn_row->addWidget(clear_btn);
    input_card_layout->addLayout(btn_row);

    // Thin separator
    auto* input_sep = new QFrame(input_card);
    input_sep->setFrameShape(QFrame::HLine);
    input_sep->setStyleSheet("background: rgba(7,135,255,0.12); border: none; max-height: 1px;");
    input_card_layout->addWidget(input_sep);

    // Text input + send/stop
    auto* send_row = new QHBoxLayout();
    send_row->setSpacing(8);
    ai_input_edit_ = new QLineEdit(input_card);
    ai_input_edit_->setPlaceholderText(
        QString::fromUtf8("Hỏi về malware, phân tích phát hiện, tư vấn bảo mật..."));
    ai_input_edit_->setEnabled(false);
    ai_input_edit_->setMinimumHeight(34);
    ai_input_edit_->setStyleSheet(
        "QLineEdit { background: transparent; border: none; color: #e8f4ff;"
        " font-size: 10pt; padding: 0 4px; }"
        "QLineEdit:disabled { color: rgba(255,255,255,0.25); }"
        "QLineEdit::placeholder { color: rgba(255,255,255,0.22); }");
    send_row->addWidget(ai_input_edit_, 1);

    ai_send_btn_ = new QPushButton(QString::fromUtf8("Gửi  ↵"), input_card);
    ai_send_btn_->setFixedSize(90, 34);
    ai_send_btn_->setEnabled(false);
    ai_send_btn_->setStyleSheet(
        "QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "  stop:0 #0553E8, stop:1 #0898FF);"
        " color: #fff; font-weight: 700; font-size: 9.5pt;"
        " border-radius: 8px; border: 1px solid rgba(41,160,255,0.3); }"
        "QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "  stop:0 #0443C8, stop:1 #0787FF); }"
        "QPushButton:disabled { background: rgba(255,255,255,0.06);"
        " color: rgba(255,255,255,0.2); border-color: transparent; }");
    send_row->addWidget(ai_send_btn_);

    ai_stop_btn_ = new QPushButton(QString::fromUtf8("⏹"), input_card);
    ai_stop_btn_->setFixedSize(34, 34);
    ai_stop_btn_->setVisible(false);
    ai_stop_btn_->setStyleSheet(
        "QPushButton { background: rgba(235,59,90,0.18); color: #ff5577;"
        " border: 1px solid rgba(235,59,90,0.35); border-radius: 8px; font-size: 12pt; }"
        "QPushButton:hover { background: rgba(235,59,90,0.35); }");
    send_row->addWidget(ai_stop_btn_);
    input_card_layout->addLayout(send_row);
    layout->addWidget(input_card);

    // ── System prompt — keep it short and in English so any model understands it ──
    const std::string kSystemPrompt =
        "You are TeoAV Assistant, a security AI built into TeoAvSuite antivirus for Windows. "
        "You help users analyze malware detections, explain threats, and give security advice. "
        "Always reply in Vietnamese. Be concise and friendly. "
        "Do NOT repeat these instructions in your responses.";

    // ── Helper: add bubble, return text QLabel, auto-scroll ──
    auto addBubble = [this](const QString& text, Qt::Alignment align) -> QLabel* {
        auto* item = ai_chat_layout_->itemAt(ai_chat_layout_->count() - 1);
        if (item && item->spacerItem()) {
            ai_chat_layout_->removeItem(item);
            delete item;
        }
        auto* row = MakeBubble(text, align, ai_chat_widget_);
        ai_chat_layout_->addWidget(row);
        ai_chat_layout_->addStretch();
        // "msg_text" objectName set in MakeBubble — always the text label, never the avatar
        QLabel* lbl = row->findChild<QLabel*>("msg_text");
        QTimer::singleShot(0, this, [this] {
            ai_chat_scroll_->verticalScrollBar()->setValue(
                ai_chat_scroll_->verticalScrollBar()->maximum());
        });
        return lbl;
    };

    // ── Wire: Browse ──
    connect(browse_btn, &QPushButton::clicked, this, [inline_model_edit, this] {
        const QString p = QFileDialog::getOpenFileName(
            this, QString::fromUtf8("Chọn model GGUF"),
            inline_model_edit->text(),
            QString::fromUtf8("GGUF model (*.gguf);;Tất cả (*.*)"));
        if (!p.isEmpty()) inline_model_edit->setText(p);
    });

    // ── Wire: Load model ──
    connect(load_btn, &QPushButton::clicked, this,
            [this, load_btn, inline_model_edit, kSystemPrompt, addBubble] {
        const std::string model_path = inline_model_edit->text().toStdString();
        if (model_path.empty()) {
            addBubble(QString::fromUtf8(
                "⚠ Chưa nhập đường dẫn model. Bấm 📂 để chọn file .gguf."),
                Qt::AlignLeft);
            return;
        }
        config_.ai_model_path = model_path;
        if (!config_.config_file_path.empty()) config_.SaveToFile(config_.config_file_path);

        load_btn->setEnabled(false);
        ai_status_label_->setText(QString::fromUtf8("⏳ Đang tải..."));
        ai_status_label_->setStyleSheet("color: #f9ca24; font-size: 9pt; font-style: italic;");

        std::thread([this, model_path, load_btn, kSystemPrompt, addBubble] {
            std::string err;
            try {
                ai_assistant_ = std::make_unique<avai::LlmAssistant>(model_path, 4096, 0);
                ai_history_.clear();
                ai_history_.push_back({"system", kSystemPrompt});
            } catch (const std::exception& e) { err = e.what(); }

            QMetaObject::invokeMethod(this, [this, err, load_btn, addBubble] {
                if (!err.empty()) {
                    ai_status_label_->setText(QString::fromUtf8("✗ Lỗi"));
                    ai_status_label_->setStyleSheet("color: #eb3b5a; font-size: 9pt;");
                    addBubble(QString::fromUtf8("⚠ ") + QString::fromUtf8(err.c_str()),
                              Qt::AlignLeft);
                    load_btn->setEnabled(true);
                    return;
                }
                const auto sep = config_.ai_model_path.find_last_of("/\\");
                const std::string name = sep != std::string::npos
                    ? config_.ai_model_path.substr(sep + 1) : config_.ai_model_path;
                ai_status_label_->setText(
                    QString::fromUtf8("✓ GPU • %1").arg(QString::fromUtf8(name.c_str())));
                ai_status_label_->setStyleSheet("color: #2ecc71; font-size: 9pt;");
                ai_input_edit_->setEnabled(true);
                ai_send_btn_->setEnabled(true);
                addBubble(
                    QString::fromUtf8(
                        "Xin chào! Tôi là TeoAV Assistant 🛡\n\n"
                        "Tôi có thể giúp bạn:\n"
                        "• Giải thích các phát hiện malware\n"
                        "• Phân tích rule_id và evidence\n"
                        "• Đề xuất biện pháp xử lý\n"
                        "• Tư vấn về an ninh mạng\n\n"
                        "Bấm 📎 để đính kèm phát hiện gần nhất, hoặc hỏi thẳng bên dưới."),
                    Qt::AlignLeft);
            }, Qt::QueuedConnection);
        }).detach();
    });

    // ── Wire: Send message ──
    auto sendMessage = [this, addBubble] {
        // Hard re-entrancy guard — prevents double-fire from returnPressed+clicked race
        if (ai_sending_ || !ai_assistant_) return;
        const QString user_text = ai_input_edit_->text().trimmed();
        if (user_text.isEmpty()) return;

        ai_sending_ = true;
        ai_input_edit_->clear();
        ai_send_btn_->setEnabled(false);
        ai_input_edit_->setEnabled(false);
        ai_stop_btn_->setVisible(true);
        ai_status_label_->setText(QString::fromUtf8("● Đang trả lời..."));
        ai_status_label_->setStyleSheet("color: #f9ca24; font-size: 9pt; font-style: italic;");

        addBubble(user_text, Qt::AlignRight);

        // Keep history to last 10 turns (system + 5 pairs) to avoid context overflow
        ai_history_.push_back({"user", user_text.toStdString()});
        if (ai_history_.size() > 11) {
            // Always keep index 0 (system prompt), drop oldest user/assistant pair
            ai_history_.erase(ai_history_.begin() + 1, ai_history_.begin() + 3);
        }

        ai_typing_text_.clear();
        ai_typing_label_ = addBubble(QString::fromUtf8(""), Qt::AlignLeft);

        ai_assistant_->GenerateAsync(ai_history_,
            [this](const std::string& token, bool done) {
                QMetaObject::invokeMethod(this, [this, token, done] {
                    if (!token.empty() && ai_typing_label_) {
                        ai_typing_text_ += QString::fromUtf8(token.c_str());
                        // Plain text during streaming to avoid partial-HTML issues
                        ai_typing_label_->setTextFormat(Qt::PlainText);
                        ai_typing_label_->setText(ai_typing_text_ + QString::fromUtf8("\xe2\x96\x8c")); // ▌
                        ai_chat_scroll_->verticalScrollBar()->setValue(
                            ai_chat_scroll_->verticalScrollBar()->maximum());
                    }
                    if (done) {
                        if (ai_typing_label_) {
                            if (ai_typing_text_.isEmpty()) {
                                ai_typing_label_->setText(QString::fromUtf8("(Không có phản hồi)"));
                            } else {
                                // Render markdown as HTML on the completed response
                                ai_typing_label_->setTextFormat(Qt::RichText);
                                ai_typing_label_->setText(MarkdownToHtml(ai_typing_text_));
                            }
                        }
                        if (!ai_typing_text_.isEmpty())
                            ai_history_.push_back({"assistant", ai_typing_text_.toStdString()});
                        ai_typing_label_ = nullptr;
                        ai_sending_ = false;
                        ai_send_btn_->setEnabled(true);
                        ai_input_edit_->setEnabled(true);
                        ai_input_edit_->setFocus();
                        ai_stop_btn_->setVisible(false);
                        ai_status_label_->setText(QString::fromUtf8("✓ Sẵn sàng"));
                        ai_status_label_->setStyleSheet("color: #2ecc71; font-size: 9pt;");
                    }
                }, Qt::QueuedConnection);
            });
    };

    connect(ai_send_btn_,  &QPushButton::clicked,       this, sendMessage);
    connect(ai_input_edit_,&QLineEdit::returnPressed,   this, sendMessage);
    connect(ai_stop_btn_,  &QPushButton::clicked,       this, [this] {
        if (ai_assistant_) {
            ai_assistant_->Abort();
            // Abort doesn't call done callback — reset state manually after brief delay
            QTimer::singleShot(200, this, [this] {
                if (ai_typing_label_) ai_typing_label_->setText(ai_typing_text_);
                ai_typing_label_ = nullptr;
                ai_sending_ = false;
                ai_send_btn_->setEnabled(true);
                ai_input_edit_->setEnabled(true);
                ai_stop_btn_->setVisible(false);
                ai_status_label_->setText(QString::fromUtf8("⏹ Đã dừng"));
                ai_status_label_->setStyleSheet("color: rgba(255,255,255,0.4); font-size: 9pt;");
            });
        }
    });

    // ── Wire: Clear chat ──
    connect(clear_btn, &QPushButton::clicked, this, [this, kSystemPrompt] {
        // Remove all bubble widgets (keep the stretch at index 0)
        while (ai_chat_layout_->count() > 0) {
            auto* item = ai_chat_layout_->takeAt(0);
            if (item->widget()) item->widget()->deleteLater();
            delete item;
        }
        ai_chat_layout_->addStretch();
        ai_typing_label_ = nullptr;
        ai_typing_text_.clear();
        ai_history_.clear();
        if (ai_assistant_) ai_history_.push_back({"system", kSystemPrompt});
    });

    // ── Wire: Inject detections ──
    connect(inject_btn, &QPushButton::clicked, this, [this] {
        const auto recent = engine_->RecentDetections(5);
        if (recent.empty()) {
            ai_input_edit_->setText(QString::fromUtf8("Chưa có phát hiện nào."));
            return;
        }
        std::string ctx = "Các phát hiện malware gần nhất trong TeoAvSuite:\n";
        for (const auto& ev : recent) {
            ctx += "• " + ev.rule_id + " [" +
                   (ev.severity == avcore::Severity::Malicious ? "MALICIOUS" :
                    ev.severity == avcore::Severity::Suspicious ? "SUSPICIOUS" : "INFO") +
                   "] " + ev.target_path + "\n  → " + ev.evidence + "\n";
        }
        ctx += "\nPhân tích và đề xuất biện pháp xử lý?";
        ai_input_edit_->setText(QString::fromUtf8(ctx.c_str()));
    });

#endif  // removed — BuildAiPage is in main_window_ai.cpp

void MainWindow::OnScanPersistenceClicked() {
    scan_progress_->setRange(0, 3);
    scan_progress_->setValue(0);
    scan_progress_->setVisible(true);
    scan_files_label_->setText(QString::fromUtf8("Đang quét persistence..."));
    scan_files_label_->setVisible(true);

    const int detections_before = static_cast<int>(engine_->RecentDetections(10000).size());

    RunScanInBackground([this, detections_before] {
        engine_->ScanPersistence([this](int current, int total) {
            QMetaObject::invokeMethod(this, [this, current, total] {
                scan_progress_->setRange(0, total);
                scan_progress_->setValue(current);
                const char* steps[] = {"Scheduled Tasks", "Services", "WMI Subscriptions", "Xong"};
                if (current <= 3)
                    scan_files_label_->setText(
                        QString::fromUtf8("Bước %1/3: %2").arg(current + 1)
                            .arg(steps[current < 4 ? current : 3]));
            }, Qt::QueuedConnection);
        });

        const int new_detections =
            static_cast<int>(engine_->RecentDetections(10000).size()) - detections_before;
        QMetaObject::invokeMethod(this, [this, new_detections] {
            status_label_->setText(
                new_detections > 0
                    ? QString::fromUtf8("Persistence scan: phát hiện %1 mối đe dọa!")
                          .arg(new_detections)
                    : QString::fromUtf8("Persistence scan: không phát hiện mối đe dọa."));
        }, Qt::QueuedConnection);
    });
}

void MainWindow::OnCancelScanClicked() {
    engine_->CancelScan();
    status_label_->setText(QString::fromUtf8("Đang hủy..."));
    cancel_scan_button_->setEnabled(false);
}

void MainWindow::AppendEtwRow(const avbehavior::ProcessEvent& event) {
    // The ETW page is not built in the current 4-core-page layout, so etw_table_
    // is null even though live ETW events are still delivered here via a queued
    // connection. Dereferencing it crashed the app a few seconds after launch
    // (null QTableWidget::rowCount, the very first process-creation event). Bail
    // out until/unless the ETW view is reinstated.
    if (!etw_table_) return;

    // Cap at 500 rows — drop oldest when full
    if (etw_table_->rowCount() >= 500) etw_table_->removeRow(0);

    const int row = etw_table_->rowCount();
    etw_table_->insertRow(row);

    const auto t = std::chrono::system_clock::to_time_t(event.start_time);
    etw_table_->setItem(row, 0,
        new QTableWidgetItem(QDateTime::fromSecsSinceEpoch(static_cast<qint64>(t))
                                 .toString("HH:mm:ss")));
    etw_table_->setItem(row, 1, new QTableWidgetItem(QString::number(event.process_id)));
    etw_table_->setItem(row, 2, new QTableWidgetItem(QString::number(event.parent_process_id)));
    etw_table_->setItem(row, 3,
        new QTableWidgetItem(QString::fromUtf8(
            std::filesystem::path(event.image_path).filename().string().c_str())));
    etw_table_->setItem(row, 4,
        new QTableWidgetItem(QString::fromUtf8(event.command_line.c_str())));

    etw_table_->scrollToBottom();
}

// ─── Network Monitor Page — defined in main_window_network.cpp ────────────────
#if 0 // preserved for reference; actual implementation is in main_window_network.cpp
QWidget* MainWindow::BuildNetworkPage_UNUSED() {
    auto* page = new QWidget();
    page->setStyleSheet("QWidget { background: #0D0906; }");

    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(24, 16, 24, 16);
    root->setSpacing(14);

    // Header row
    auto* hdr = new QHBoxLayout();
    hdr->setSpacing(10);

    auto* hdr_icon = new IconWidget(IconWidget::Wifi, 22, QColor(0xFF,0x7A,0x00));
    hdr->addWidget(hdr_icon);

    auto* hdr_title = new QLabel(QString::fromUtf8("Network Monitor"), page);
    hdr_title->setStyleSheet(
        "font-size: 15pt; font-weight: 800; color: #FFFFFF; background: transparent;");
    hdr->addWidget(hdr_title);
    hdr->addStretch();

    auto* refresh_btn = new QPushButton(page);
    {
        auto* rlay = new QHBoxLayout(refresh_btn);
        rlay->setContentsMargins(10,0,10,0);
        rlay->setSpacing(6);
        auto* r_ico = new IconWidget(IconWidget::RefreshCw, 15, QColor(0xFF,0x7A,0x00));
        auto* r_lbl = new QLabel(QString::fromUtf8("L\xe1\xba\xa0m m\xe1\xbb\x9bi"), refresh_btn);
        r_lbl->setStyleSheet("background:transparent;color:#FF7A00;font-size:9pt;font-weight:600;");
        rlay->addWidget(r_ico);
        rlay->addWidget(r_lbl);
    }
    refresh_btn->setFixedHeight(32);
    refresh_btn->setMinimumWidth(110);
    refresh_btn->setStyleSheet(
        "QPushButton { background: rgba(255,122,0,0.10); border: 1px solid rgba(255,122,0,0.30);"
        " border-radius: 8px; }"
        "QPushButton:hover { background: rgba(255,122,0,0.22); }");
    hdr->addWidget(refresh_btn);
    root->addLayout(hdr);

    // Stat cards row
    auto* stats_row = new QHBoxLayout();
    stats_row->setSpacing(12);

    struct StatDef { const char* label; QLabel** target; QColor accent; };
    StatDef stat_defs[] = {
        { "T\xe1\xbb\x95ng k\xe1\xba\xbft n\xe1\xbb\x91i", &net_stat_total_,   QColor(0xFF,0x7A,0x00) },
        { "Established",             &net_stat_estab_,   QColor(0x4A,0xDE,0x80) },
        { "Listening",               &net_stat_listen_,  QColor(0x07,0x87,0xFF) },
    };
    for (auto& sd : stat_defs) {
        auto* card = new QFrame(page);
        card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        card->setFixedHeight(64);
        card->setStyleSheet(
            QString("QFrame { background: #1A100A; border: 1px solid rgba(%1,%2,%3,0.25);"
                    " border-radius: 10px; }")
                .arg(sd.accent.red()).arg(sd.accent.green()).arg(sd.accent.blue()));
        auto* cl = new QVBoxLayout(card);
        cl->setContentsMargins(14, 8, 14, 8);
        cl->setSpacing(2);
        *sd.target = new QLabel("—", card);
        (*sd.target)->setStyleSheet(
            QString("font-size: 20pt; font-weight: 800; color: rgb(%1,%2,%3);"
                    " background: transparent;")
                .arg(sd.accent.red()).arg(sd.accent.green()).arg(sd.accent.blue()));
        auto* lbl = new QLabel(QString::fromUtf8(sd.label), card);
        lbl->setStyleSheet("font-size: 8pt; color: rgba(199,182,162,0.7); background: transparent;");
        cl->addWidget(*sd.target);
        cl->addWidget(lbl);
        stats_row->addWidget(card);
    }
    root->addLayout(stats_row);

    // Port scanner tool
    auto* scan_card = new QFrame(page);
    scan_card->setStyleSheet(
        "QFrame { background: #1A100A; border: 1px solid rgba(255,122,0,0.18);"
        " border-radius: 10px; }");
    auto* scan_row = new QHBoxLayout(scan_card);
    scan_row->setContentsMargins(12, 8, 12, 8);
    scan_row->setSpacing(8);

    auto* scan_ico = new IconWidget(IconWidget::Search, 15, QColor(0xFF,0x7A,0x00));
    scan_row->addWidget(scan_ico);

    auto* scan_lbl = new QLabel(QString::fromUtf8("Port Scanner:"), scan_card);
    scan_lbl->setStyleSheet("color:#FF7A00;font-size:9pt;font-weight:700;background:transparent;");
    scan_row->addWidget(scan_lbl);

    auto* host_edit = new QLineEdit(scan_card);
    host_edit->setPlaceholderText(QString::fromUtf8("Host (vd: 192.168.1.1)"));
    host_edit->setFixedWidth(180);
    host_edit->setStyleSheet(
        "QLineEdit { background: rgba(255,122,0,0.07); border: 1px solid rgba(255,122,0,0.2);"
        " border-radius: 6px; color: #fff; font-size: 9pt; padding: 4px 8px; }"
        "QLineEdit:focus { border-color: rgba(255,122,0,0.5); }");
    scan_row->addWidget(host_edit);

    auto* ports_edit = new QLineEdit(scan_card);
    ports_edit->setPlaceholderText(QString::fromUtf8("Cổng (vd: 80,443,3389)"));
    ports_edit->setFixedWidth(180);
    ports_edit->setStyleSheet(host_edit->styleSheet());
    scan_row->addWidget(ports_edit);

    auto* scan_btn = new QPushButton(QString::fromUtf8("Quét"), scan_card);
    scan_btn->setFixedSize(70, 28);
    scan_btn->setStyleSheet(
        "QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "  stop:0 #C05500,stop:1 #FF7A00); color:#fff;font-weight:700;font-size:9pt;"
        " border-radius:6px;border:none; }"
        "QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        "  stop:0 #D06000,stop:1 #FF9030); }"
        "QPushButton:disabled { background: rgba(255,255,255,0.07);"
        " color:rgba(255,255,255,0.2); }");
    scan_row->addWidget(scan_btn);
    scan_row->addStretch();

    auto* scan_result = new QLabel("", scan_card);
    scan_result->setStyleSheet("color:rgba(199,182,162,0.8);font-size:8.5pt;background:transparent;");
    scan_row->addWidget(scan_result);
    root->addWidget(scan_card);

    // Connections table
    auto* tbl_card = new QFrame(page);
    tbl_card->setStyleSheet(
        "QFrame { background: #1A100A; border: 1px solid rgba(255,122,0,0.15);"
        " border-radius: 10px; }");
    auto* tbl_layout = new QVBoxLayout(tbl_card);
    tbl_layout->setContentsMargins(0, 0, 0, 0);
    tbl_layout->setSpacing(0);

    // Table header
    auto* tbl_hdr = new QWidget(tbl_card);
    tbl_hdr->setStyleSheet(
        "background: rgba(255,122,0,0.08); border-radius: 10px 10px 0 0;"
        "border-bottom: 1px solid rgba(255,122,0,0.15);");
    auto* tbl_hdr_lay = new QHBoxLayout(tbl_hdr);
    tbl_hdr_lay->setContentsMargins(14, 8, 14, 8);
    auto* tbl_hdr_lbl = new QLabel(
        QString::fromUtf8("K\xe1\xba\xbft n\xe1\xbb\x91i m\xe1\xba\xa1ng"), tbl_hdr);
    tbl_hdr_lbl->setStyleSheet("font-size:10pt;font-weight:700;color:#FF7A00;background:transparent;");
    tbl_hdr_lay->addWidget(tbl_hdr_lbl);
    tbl_layout->addWidget(tbl_hdr);

    net_conn_table_ = new QTableWidget(0, 6, tbl_card);
    net_conn_table_->setHorizontalHeaderLabels(
        { "Proto", QString::fromUtf8("Local Address"),
          QString::fromUtf8("Remote Address"), "State", "PID", "Process" });
    net_conn_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    net_conn_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    net_conn_table_->setSelectionMode(QAbstractItemView::SingleSelection);
    net_conn_table_->verticalHeader()->setVisible(false);
    net_conn_table_->setShowGrid(false);
    net_conn_table_->setAlternatingRowColors(true);
    net_conn_table_->setSortingEnabled(true);
    net_conn_table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    net_conn_table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    net_conn_table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    net_conn_table_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    net_conn_table_->setStyleSheet(
        "QTableWidget {"
        " background: transparent; alternate-background-color: rgba(255,122,0,0.04);"
        " color: #E8DACE; font-size: 8.5pt; border: none; gridline-color: transparent; }"
        "QTableWidget::item { padding: 4px 8px; }"
        "QTableWidget::item:selected { background: rgba(255,122,0,0.18); color: #fff; }"
        "QHeaderView::section {"
        " background: transparent; color: rgba(255,122,0,0.8);"
        " font-size: 8pt; font-weight: 700; border: none;"
        " border-bottom: 1px solid rgba(255,122,0,0.2); padding: 4px 8px; }");
    tbl_layout->addWidget(net_conn_table_);
    root->addWidget(tbl_card, 1);

    // Auto-refresh timer (every 5 seconds)
    auto* refresh_timer = new QTimer(page);
    refresh_timer->setInterval(5000);
    connect(refresh_timer, &QTimer::timeout, this, &MainWindow::RefreshNetworkConnections);
    refresh_timer->start();

    connect(refresh_btn, &QPushButton::clicked, this, &MainWindow::RefreshNetworkConnections);

    // Port scanner logic
    connect(scan_btn, &QPushButton::clicked, this,
            [this, host_edit, ports_edit, scan_btn, scan_result] {
        const QString host = host_edit->text().trimmed();
        const QString ports_str = ports_edit->text().trimmed();
        if (host.isEmpty() || ports_str.isEmpty()) {
            scan_result->setText(QString::fromUtf8("\xe2\x9a\xa0 Nh\xe1\xba\xadp host v\xc3\xa0 c\xe1\xbb\x95ng"));
            return;
        }
        scan_btn->setEnabled(false);
        scan_result->setText(QString::fromUtf8("\xe2\x8f\xb3 \xc4\x90" "ang qu\xe1\xba\xabt..."));

        const QStringList port_list = ports_str.split(',', Qt::SkipEmptyParts);
        std::thread([this, host, port_list, scan_btn, scan_result] {
            QString open_ports, closed_ports;
            int open_count = 0, closed_count = 0;
            for (const QString& p_str : port_list) {
                const int port = p_str.trimmed().toInt();
                if (port <= 0 || port > 65535) continue;

                auto* proc = new QProcess();
                proc->start("powershell",
                    QStringList() << "-Command"
                    << QString("(New-Object System.Net.Sockets.TcpClient)."
                               "Connect('%1',%2); 'OPEN'").arg(host).arg(port));
                const bool finished = proc->waitForFinished(2000);
                const bool success = finished && proc->exitCode() == 0;
                delete proc;

                if (success) {
                    if (!open_ports.isEmpty()) open_ports += ", ";
                    open_ports += QString::number(port);
                    ++open_count;
                } else {
                    ++closed_count;
                }
            }
            const QString result = open_count > 0
                ? QString::fromUtf8("\xe2\x9c\x93 M\xe1\xbb\x9f: [%1] \xe2\x80\xa2 \xc4\x90\xc3\xb3ng: %2")
                      .arg(open_ports).arg(closed_count)
                : QString::fromUtf8("\xf0\x9f\x94\x92 T\xe1\xba\xa5t c\xe1\xba\xa3 %1 c\xe1\xbb\x95ng \xc4\x91\xc3\xb3ng")
                      .arg(closed_count);

            QMetaObject::invokeMethod(this, [scan_btn, scan_result, result] {
                scan_result->setText(result);
                scan_btn->setEnabled(true);
            }, Qt::QueuedConnection);
        }).detach();
    });

    // Initial load
    QTimer::singleShot(0, this, &MainWindow::RefreshNetworkConnections);

    return page;
}

void MainWindow::RefreshNetworkConnections() {
    auto* proc = new QProcess(this);
    connect(proc, QOverload<int,QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, proc](int /*code*/, QProcess::ExitStatus) {
        const QString raw = QString::fromLocal8Bit(proc->readAllStandardOutput());
        proc->deleteLater();

        struct Conn {
            QString proto, local, remote, state;
            int pid = 0;
        };
        QVector<Conn> conns;
        int total = 0, estab = 0, listen = 0;

        for (const QString& line : raw.split('\n')) {
            const QString t = line.trimmed();
            if (t.isEmpty() || t.startsWith("Active") || t.startsWith("Proto")) continue;
            const QStringList parts = t.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
            if (parts.size() < 3) continue;

            Conn c;
            c.proto = parts[0];
            if (c.proto.compare("TCP", Qt::CaseInsensitive) == 0) {
                if (parts.size() >= 5) {
                    c.local  = parts[1];
                    c.remote = parts[2];
                    c.state  = parts[3];
                    c.pid    = parts[4].toInt();
                }
            } else if (c.proto.compare("UDP", Qt::CaseInsensitive) == 0) {
                if (parts.size() >= 4) {
                    c.local  = parts[1];
                    c.remote = parts[2];
                    c.state  = "*";
                    c.pid    = parts[3].toInt();
                }
            } else {
                continue;
            }
            conns.append(c);
            ++total;
            if (c.state.compare("ESTABLISHED", Qt::CaseInsensitive) == 0) ++estab;
            if (c.state.compare("LISTENING",   Qt::CaseInsensitive) == 0) ++listen;
        }

        // Process name lookup via single tasklist call
        QHash<int,QString> pid_names;
        {
            QProcess tp;
            tp.start("tasklist", QStringList() << "/FO" << "CSV" << "/NH");
            if (tp.waitForFinished(3000)) {
                const QString tl = QString::fromLocal8Bit(tp.readAllStandardOutput());
                for (const QString& row : tl.split('\n')) {
                    const QStringList cols = row.split(',');
                    if (cols.size() >= 2) {
                        const int pid = cols[1].trimmed().replace("\"","").toInt();
                        const QString name = cols[0].trimmed().replace("\"","");
                        if (pid > 0) pid_names[pid] = name;
                    }
                }
            }
        }

        // Update stats
        net_stat_total_ ->setText(QString::number(total));
        net_stat_estab_ ->setText(QString::number(estab));
        net_stat_listen_->setText(QString::number(listen));

        // Rebuild table
        net_conn_table_->setSortingEnabled(false);
        net_conn_table_->setRowCount(0);
        net_conn_table_->setRowCount(conns.size());

        for (int i = 0; i < conns.size(); ++i) {
            const auto& c = conns[i];
            net_conn_table_->setItem(i, 0, new QTableWidgetItem(c.proto));
            net_conn_table_->setItem(i, 1, new QTableWidgetItem(c.local));
            net_conn_table_->setItem(i, 2, new QTableWidgetItem(c.remote));

            auto* state_item = new QTableWidgetItem(c.state);
            if (c.state.compare("ESTABLISHED", Qt::CaseInsensitive) == 0)
                state_item->setForeground(QColor(0x4A,0xDE,0x80));
            else if (c.state.compare("LISTENING", Qt::CaseInsensitive) == 0)
                state_item->setForeground(QColor(0xFF,0xB7,0x66));
            else if (c.state.compare("TIME_WAIT", Qt::CaseInsensitive) == 0)
                state_item->setForeground(QColor(0xFF,0x5A,0x6A));
            net_conn_table_->setItem(i, 3, state_item);

            net_conn_table_->setItem(i, 4,
                new QTableWidgetItem(c.pid > 0 ? QString::number(c.pid) : ""));
            net_conn_table_->setItem(i, 5,
                new QTableWidgetItem(pid_names.value(c.pid, "—")));
        }

        net_conn_table_->setSortingEnabled(true);
    });

    proc->start("netstat", QStringList() << "-ano");
}
#endif // 0 — end of preserved-reference block for BuildNetworkPage / RefreshNetworkConnections

} // namespace avdashboard
