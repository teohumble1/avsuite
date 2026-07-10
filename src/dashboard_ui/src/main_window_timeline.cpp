// main_window_timeline.cpp — Threat detection timeline visualization
// Shows when threats were detected over the last 24 hours with severity clustering

#include "main_window.hpp"

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QDateTime>
#include <QVector>
#include <QTimer>
#include <array>
#include <cmath>

#include "avcore/severity.hpp"
#include "theme.hpp"

namespace avdashboard {

namespace {

// Severity is only 3-valued in avcore (Info/Suspicious/Malicious); mapped
// onto the 0-3 low/med/high/critical scale the canvas already draws.
// Medium (1) is never produced from real data -- kept in the enum/legend
// only because the canvas's color scale supports it.
int SeverityTier(avcore::Severity s) {
    switch (s) {
        case avcore::Severity::Malicious: return 3;
        case avcore::Severity::Suspicious: return 2;
        case avcore::Severity::Info: return 0;
    }
    return 0;
}

} // namespace

struct TimelineEvent {
    QDateTime timestamp;
    QString threat_type;
    int severity;  // 0=low, 1=med, 2=high, 3=critical
    QString description;
};

class TimelineCanvas : public QWidget {
public:
    explicit TimelineCanvas(QWidget* parent = nullptr) : QWidget(parent) {
        setMinimumHeight(200);
        setStyleSheet(QString("background:%1; border:1px solid %2; border-radius:%3px;")
                          .arg(theme::Surface).arg(theme::Border).arg(theme::RadiusLg));
    }

    void setEvents(QVector<TimelineEvent> events) {
        events_ = std::move(events);
        update();
    }

protected:
    void paintEvent(QPaintEvent* event) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);

        int w = width();
        int h = height();

        if (w < 100 || h < 100) return;  // Prevent crash on uninitialized size

        // Draw timeline axis
        painter.setPen(QPen(QColor(theme::Border), 2));
        painter.drawLine(50, h - 50, w - 50, h - 50);

        if (events_.empty()) {
            painter.setPen(QPen(QColor(theme::Dim)));
            painter.setFont(QFont("Segoe UI", 9));
            painter.drawText(rect(), Qt::AlignCenter, "No detections in the last 24 hours.");
            return;
        }

        // Find time range (24 hours)
        QDateTime now = QDateTime::currentDateTime();
        QDateTime start = now.addSecs(-86400);

        // Draw time labels
        painter.setPen(QPen(QColor(theme::Dim)));
        painter.setFont(QFont("Arial", 8));
        for (int i = 0; i <= 24; i += 6) {
            int x = 50 + (i * (w - 100)) / 24;
            painter.drawText(x - 15, h - 30, 30, 20, Qt::AlignCenter,
                           QString::number(i) + "h");
        }

        // Draw events as dots
        for (const auto& evt : events_) {
            double elapsed = start.secsTo(evt.timestamp);
            double progress = elapsed / 86400.0;
            if (progress < 0 || progress > 1) continue;

            int x = 50 + static_cast<int>(progress * (w - 100));
            int y = h - 50;

            // Color by severity (semantic tokens)
            QColor color;
            switch (evt.severity) {
                case 3: color = QColor(theme::Danger); break;  // malicious
                case 2: color = QColor(theme::Warn);   break;  // suspicious
                case 1: color = QColor(theme::Info);   break;  // medium (unused)
                default: color = QColor(theme::Safe);  break;  // low / info
            }

            painter.setBrush(color);
            painter.setPen(Qt::NoPen);
            painter.drawEllipse(x - 6, y - 30 - (evt.severity * 10), 12, 12);

            // Draw tooltip hint
            painter.setPen(QPen(QColor(theme::Dim)));
            painter.setFont(QFont("Segoe UI", 7));
            painter.drawText(x - 20, y - 50 - (evt.severity * 10), 40, 20, Qt::AlignCenter,
                           evt.threat_type.left(5));
        }
    }

private:
    QVector<TimelineEvent> events_;
};

QWidget* BuildTimelinePage(QWidget* parent) {
    auto* win = qobject_cast<MainWindow*>(parent);
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setSpacing(theme::Space3);
    layout->setContentsMargins(theme::Space6, theme::Space6, theme::Space6, theme::Space6);

    layout->addWidget(theme::BuildPageHeader(
        "Threat Detection Timeline",
        "Detection history over the last 24 hours — severity clustered by color"));

    // Timeline canvas
    auto* canvas = new TimelineCanvas(page);
    layout->addWidget(canvas, 1);

    // Legend
    auto* legend = new QHBoxLayout();
    auto add_legend = [legend](const QString& color_hex, const QString& label) {
        auto* box = new QWidget();
        box->setStyleSheet(QString("background:%1; border-radius:4px;").arg(color_hex));
        box->setFixedSize(12, 12);
        auto* h = new QHBoxLayout(box);
        h->setContentsMargins(0, 0, 0, 0);
        box->setLayout(h);

        auto* lbl = new QLabel(label);
        lbl->setStyleSheet(QString("color:%1; font-size:%2px;").arg(theme::Muted).arg(theme::FontCaption));

        legend->addWidget(box);
        legend->addWidget(lbl);
    };
    add_legend(theme::Danger, "Malicious");
    add_legend(theme::Warn, "Suspicious");
    add_legend(theme::Safe, "Info");
    legend->addStretch();
    layout->addLayout(legend);

    // Stats (computed from real detection history below)
    auto* stats = new QLabel("Loading...");
    stats->setStyleSheet(QString("color:%1; font-size:%2px; padding:10px;").arg(theme::Dim).arg(theme::FontCaption));
    layout->addWidget(stats);

    page->setStyleSheet(QString("background:%1;").arg(theme::Bg));

    if (!win) return page;

    auto refresh = [win, canvas, stats]() {
        // 10000 is generous headroom to reliably cover the last 48h even on
        // a busy install; RecentDetections is already most-recent-first.
        const auto history = win->GetRecentDetections(10000);

        const auto now = std::chrono::system_clock::now();
        const auto day_ago = now - std::chrono::hours(24);
        const auto two_days_ago = now - std::chrono::hours(48);

        QVector<TimelineEvent> events;
        int critical_count = 0, high_count = 0;
        int prior_day_count = 0;
        std::array<int, 24> hour_counts{};
        hour_counts.fill(0);

        for (const auto& ev : history) {
            if (ev.timestamp < two_days_ago) continue;

            const auto secs = std::chrono::system_clock::to_time_t(ev.timestamp);
            const QDateTime ts = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(secs));

            if (ev.timestamp >= day_ago) {
                TimelineEvent te;
                te.timestamp = ts;
                te.threat_type = QString::fromUtf8(ev.rule_id.c_str());
                te.severity = SeverityTier(ev.severity);
                te.description = QString::fromUtf8(ev.evidence.c_str());
                events.push_back(te);

                if (ev.severity == avcore::Severity::Malicious) ++critical_count;
                else if (ev.severity == avcore::Severity::Suspicious) ++high_count;

                const int hour = static_cast<int>(24 - std::chrono::duration_cast<std::chrono::hours>(now - ev.timestamp).count());
                if (hour >= 0 && hour < 24) ++hour_counts[static_cast<std::size_t>(hour)];
            } else {
                ++prior_day_count;
            }
        }

        canvas->setEvents(events);

        int peak_hour = 0, peak_count = 0;
        for (int h = 0; h < 24; ++h) {
            if (hour_counts[static_cast<std::size_t>(h)] > peak_count) {
                peak_count = hour_counts[static_cast<std::size_t>(h)];
                peak_hour = h;
            }
        }

        const int today_count = critical_count + high_count;
        QString trend = "no prior-day data";
        if (prior_day_count > 0) {
            const double pct = (static_cast<double>(today_count - prior_day_count) / prior_day_count) * 100.0;
            trend = QString("%1%2%")
                        .arg(pct >= 0 ? QString::fromUtf8("↑ +") : QString::fromUtf8("↓ "))
                        .arg(QString::number(pct, 'f', 0));
        }

        stats->setText(QString("Today: %1 critical, %2 suspicious detections | %3 | Last 24h trend: %4")
                            .arg(critical_count)
                            .arg(high_count)
                            .arg(peak_count > 0 ? QString("Peak activity: ~%1 detection(s)/hr around %2h ago")
                                                      .arg(peak_count)
                                                      .arg(24 - peak_hour)
                                                : QString("No peak activity"))
                            .arg(trend));
    };

    refresh();
    auto* timer = new QTimer(page);
    QObject::connect(timer, &QTimer::timeout, page, refresh);
    timer->start(10000);

    return page;
}

} // namespace avdashboard
