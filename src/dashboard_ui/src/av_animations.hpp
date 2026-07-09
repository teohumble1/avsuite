// av_animations.hpp — TeoAVSuite Premium Animation & Motion System
// Windows 11 Fluent Motion / Full Orange Ecosystem
// MOC-free: all classes use QTimer+lambda, QVariantAnimation; no Q_OBJECT needed.
// Timing: micro=150ms  normal=250ms  large=380ms
// Easing: OutCubic (0.22,1,0.36,1) for all major transitions

#pragma once

#include <QAbstractAnimation>
#include <QColor>
#include <QEasingCurve>
#include <QGraphicsDropShadowEffect>
#include <QGraphicsOpacityEffect>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QTimer>
#include <QVariantAnimation>
#include <QWidget>
#include <cmath>

namespace avdashboard {

// ─── Timing constants (ms) ───────────────────────────────────────────────────
static constexpr int kAnimMicro  = 150;
static constexpr int kAnimNormal = 250;
static constexpr int kAnimLarge  = 380;

// ─── Page fade-in (QStackedWidget incoming page) ─────────────────────────────
// Call immediately after setCurrentIndex(). Fades from 0->1.
// Removes the effect on completion so it doesn't persist.
inline void AnimatePageIn(QWidget* widget, int duration = kAnimNormal) {
    if (!widget) return;
    auto* eff = new QGraphicsOpacityEffect(widget);
    eff->setOpacity(0.0);
    widget->setGraphicsEffect(eff);

    auto* anim = new QPropertyAnimation(eff, "opacity", widget);
    anim->setDuration(duration);
    anim->setStartValue(0.0);
    anim->setEndValue(1.0);
    anim->setEasingCurve(QEasingCurve::OutCubic);
    QObject::connect(anim, &QPropertyAnimation::finished, widget, [widget] {
        widget->setGraphicsEffect(nullptr);
    });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

// ─── Quick opacity flash for nav button selection ────────────────────────────
inline void AnimateNavSelect(QWidget* btn) {
    if (!btn) return;
    auto* eff = new QGraphicsOpacityEffect(btn);
    eff->setOpacity(1.0);
    btn->setGraphicsEffect(eff);
    auto* anim = new QPropertyAnimation(eff, "opacity", btn);
    anim->setDuration(350);
    anim->setKeyValueAt(0.0, 1.0);
    anim->setKeyValueAt(0.25, 0.55);
    anim->setKeyValueAt(1.0, 1.0);
    anim->setEasingCurve(QEasingCurve::InOutCubic);
    QObject::connect(anim, &QPropertyAnimation::finished, btn, [btn] {
        btn->setGraphicsEffect(nullptr);
    });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

// ─── Staggered reveal ────────────────────────────────────────────────────────
// Reveals a list of widgets with staggered fade-in animations.
inline void StaggerReveal(const QVector<QWidget*>& widgets,
                          int stagger_ms = 55,
                          int item_duration = kAnimNormal) {
    for (int i = 0; i < widgets.size(); ++i) {
        QWidget* w = widgets[i];
        auto* eff = new QGraphicsOpacityEffect(w);
        eff->setOpacity(0.0);
        w->setGraphicsEffect(eff);
        QTimer::singleShot(i * stagger_ms, w, [w, eff, item_duration] {
            auto* oa = new QPropertyAnimation(eff, "opacity", w);
            oa->setDuration(item_duration);
            oa->setStartValue(0.0);
            oa->setEndValue(1.0);
            oa->setEasingCurve(QEasingCurve::OutCubic);
            QObject::connect(oa, &QPropertyAnimation::finished, w, [w] {
                w->setGraphicsEffect(nullptr);
            });
            oa->start(QAbstractAnimation::DeleteWhenStopped);
        });
    }
}

// ─── Shake animation ─────────────────────────────────────────────────────────
// Critical threat alert: brief horizontal shake via geometry animation.
inline void ShakeWidget(QWidget* w, int intensity = 6) {
    if (!w) return;
    const QRect base = w->geometry();
    const int steps = 8;
    for (int i = 0; i < steps; ++i) {
        const int dx = (i % 2 == 0 ? intensity : -intensity) * (steps - i) / steps;
        QTimer::singleShot(i * 28, w, [w, base, dx] {
            w->setGeometry(base.adjusted(dx, 0, dx, 0));
        });
    }
    QTimer::singleShot(steps * 28, w, [w, base] { w->setGeometry(base); });
}

// ─── Glow / Drop-shadow animate ──────────────────────────────────────────────
// Animates the blur radius of a QGraphicsDropShadowEffect (existing or new).
inline void AnimateGlow(QWidget* w, QColor color, int from_blur, int to_blur,
                        int duration = kAnimNormal) {
    if (!w) return;
    auto* shadow = qobject_cast<QGraphicsDropShadowEffect*>(w->graphicsEffect());
    if (!shadow) {
        shadow = new QGraphicsDropShadowEffect(w);
        shadow->setColor(color);
        shadow->setOffset(0);
        shadow->setBlurRadius(from_blur);
        w->setGraphicsEffect(shadow);
    }
    auto* anim = new QVariantAnimation(w);
    anim->setDuration(duration);
    anim->setStartValue(static_cast<double>(from_blur));
    anim->setEndValue(static_cast<double>(to_blur));
    anim->setEasingCurve(QEasingCurve::OutCubic);
    QObject::connect(anim, &QVariantAnimation::valueChanged, shadow, [shadow](const QVariant& v) {
        shadow->setBlurRadius(v.toDouble());
    });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

// ─── Animated label counter ───────────────────────────────────────────────────
// Smoothly animates a QLabel's text from current to target numeric value.
inline void AnimateCounter(QLabel* lbl, double from, double to,
                           const QString& suffix = "",
                           int duration = kAnimNormal) {
    if (!lbl) return;
    auto* anim = new QVariantAnimation(lbl);
    anim->setDuration(duration);
    anim->setStartValue(from);
    anim->setEndValue(to);
    anim->setEasingCurve(QEasingCurve::OutCubic);
    QObject::connect(anim, &QVariantAnimation::valueChanged, lbl, [lbl, suffix](const QVariant& v) {
        const double val = v.toDouble();
        const QString text = (val >= 1000)
            ? QString::number(val / 1000.0, 'f', 1) + "K"
            : QString::number(static_cast<int>(val));
        lbl->setText(text + suffix);
    });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

// ─── Pulse ring widget ────────────────────────────────────────────────────────
// Expanding concentric rings. No Q_OBJECT: uses QTimer+lambda.
class PulseRing : public QWidget {
public:
    explicit PulseRing(QColor color = QColor(0xFF, 0x7A, 0x00), QWidget* parent = nullptr)
        : QWidget(parent), color_(color) {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_NoSystemBackground);
        timer_ = new QTimer(this);
        QObject::connect(timer_, &QTimer::timeout, this, [this] {
            phase_ = std::fmod(phase_ + 0.025, 6.2832);
            update();
        });
    }

    void start() { timer_->start(25); }
    void stop()  { timer_->stop(); update(); }
    void setColor(QColor c) { color_ = c; update(); }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const QPoint center(width() / 2, height() / 2);
        const double maxR = qMin(width(), height()) * 0.45;
        for (int i = 0; i < 3; ++i) {
            const double t = std::fmod(phase_ / 6.2832 + i / 3.0, 1.0);
            const double r = t * maxR;
            const double alpha = (1.0 - t) * 160.0;
            QColor c = color_;
            c.setAlpha(static_cast<int>(alpha));
            QPen pen(c, 1.5);
            p.setPen(pen);
            p.setBrush(Qt::NoBrush);
            p.drawEllipse(center, static_cast<int>(r), static_cast<int>(r));
        }
    }

private:
    QTimer* timer_;
    double  phase_ = 0.0;
    QColor  color_;
};

// ─── Skeleton shimmer widget ──────────────────────────────────────────────────
// Animated shimmer placeholder. No Q_OBJECT.
class SkeletonShimmer : public QWidget {
public:
    explicit SkeletonShimmer(int radius = 8, QWidget* parent = nullptr)
        : QWidget(parent), radius_(radius) {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        timer_ = new QTimer(this);
        QObject::connect(timer_, &QTimer::timeout, this, [this] {
            shimmer_pos_ = std::fmod(shimmer_pos_ + 0.018, 2.5);
            update();
        });
        timer_->start(20);
    }

    void setRadius(int r) { radius_ = r; }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setBrush(QColor(0x24, 0x17, 0x0E));
        p.setPen(Qt::NoPen);
        p.drawRoundedRect(rect(), radius_, radius_);

        const double pos = shimmer_pos_ - 0.5;
        const int x = static_cast<int>((pos / 2.0) * width() * 2.5 - width() * 0.4);
        QLinearGradient grad(x, 0, x + static_cast<int>(width() * 0.5), 0);
        grad.setColorAt(0.0, QColor(255, 255, 255, 0));
        grad.setColorAt(0.3, QColor(255, 255, 255, 14));
        grad.setColorAt(0.5, QColor(255, 255, 255, 22));
        grad.setColorAt(0.7, QColor(255, 255, 255, 14));
        grad.setColorAt(1.0, QColor(255, 255, 255, 0));
        p.fillRect(rect(), grad);
    }

private:
    QTimer* timer_;
    double  shimmer_pos_ = 0.0;
    int     radius_;
};

// ─── Typing dots widget ───────────────────────────────────────────────────────
// Three-dot animated indicator for AI thinking state. No Q_OBJECT.
class TypingDots : public QWidget {
public:
    explicit TypingDots(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedSize(40, 18);
        timer_ = new QTimer(this);
        QObject::connect(timer_, &QTimer::timeout, this, [this] {
            phase_ = (phase_ + 1) % 24;
            update();
        });
        timer_->start(80);
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        for (int i = 0; i < 3; ++i) {
            const double raw = std::sin((phase_ - i * 4) * 3.14159265 / 12.0);
            const double t = (raw > 0.0 ? raw : 0.0);
            const double alpha = t * 0.8 + 0.2;
            const double dy = t * 3.5;
            p.setBrush(QColor(255, 122, 0, static_cast<int>(alpha * 210)));
            p.setPen(Qt::NoPen);
            p.drawEllipse(QRectF(i * 13.0, 9.0 - dy - 3.0, 6.0, 6.0));
        }
    }

private:
    QTimer* timer_;
    int     phase_ = 0;
};

// ─── Ambient background ───────────────────────────────────────────────────────
// Slow-moving orange radial gradient. No Q_OBJECT.
class AmbientBackground : public QWidget {
public:
    explicit AmbientBackground(QWidget* parent = nullptr) : QWidget(parent) {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_NoSystemBackground);
        lower();
        timer_ = new QTimer(this);
        QObject::connect(timer_, &QTimer::timeout, this, [this] {
            phase_ += 0.004;
            update();
        });
        timer_->start(50);
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        const double s = std::sin(phase_) * 0.5 + 0.5;
        const double c = std::cos(phase_ * 0.73) * 0.5 + 0.5;

        QRadialGradient g1(width() * (0.68 + c * 0.14), height() * (0.1 + s * 0.1), width() * 0.55);
        g1.setColorAt(0.0, QColor(255, 122, 0, 15));
        g1.setColorAt(1.0, QColor(0, 0, 0, 0));
        p.fillRect(rect(), g1);

        QRadialGradient g2(width() * (0.05 + s * 0.08), height() * (0.78 + c * 0.1), width() * 0.4);
        g2.setColorAt(0.0, QColor(255, 90, 0, 8));
        g2.setColorAt(1.0, QColor(0, 0, 0, 0));
        p.fillRect(rect(), g2);
    }

private:
    QTimer* timer_;
    double  phase_ = 0.0;
};

// ─── RippleButton ─────────────────────────────────────────────────────────────
// QPushButton with expanding ripple on click. No Q_OBJECT.
class RippleButton : public QPushButton {
public:
    explicit RippleButton(const QString& text, QWidget* parent = nullptr)
        : QPushButton(text, parent) {
        timer_ = new QTimer(this);
        QObject::connect(timer_, &QTimer::timeout, this, [this] {
            ripple_radius_ += width() * 0.065;
            ripple_alpha_ = qMax(0, ripple_alpha_ - 7);
            update();
            if (ripple_alpha_ <= 0) {
                timer_->stop();
                ripple_radius_ = 0.0;
            }
        });
    }

    void setRippleColor(QColor c) { ripple_color_ = c; }

protected:
    void mousePressEvent(QMouseEvent* ev) override {
        QPushButton::mousePressEvent(ev);
        ripple_center_ = ev->pos();
        ripple_radius_ = 0.0;
        ripple_alpha_  = 80;
        timer_->start(16);
    }

    void paintEvent(QPaintEvent* ev) override {
        QPushButton::paintEvent(ev);
        if (ripple_radius_ > 0 && ripple_alpha_ > 0) {
            QPainter p(this);
            p.setRenderHint(QPainter::Antialiasing);
            p.setClipRect(rect());
            QColor c = ripple_color_;
            c.setAlpha(ripple_alpha_);
            p.setBrush(c);
            p.setPen(Qt::NoPen);
            p.drawEllipse(ripple_center_,
                          static_cast<int>(ripple_radius_),
                          static_cast<int>(ripple_radius_));
        }
    }

private:
    QTimer*  timer_;
    QPointF  ripple_center_;
    double   ripple_radius_ = 0.0;
    int      ripple_alpha_  = 0;
    QColor   ripple_color_{ 255, 255, 255, 55 };
};

} // namespace avdashboard
