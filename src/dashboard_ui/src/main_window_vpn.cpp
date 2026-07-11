// main_window_vpn.cpp — Premium VPN Module
// Full Orange Ecosystem / Windows 11 Fluent / Proton VPN inspired

#include "main_window.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <vector>

#include <QCheckBox>
#include <QEvent>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScrollArea>
#include <QSizePolicy>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

namespace avdashboard {

// ─── VPN Server data ─────────────────────────────────────────────────────────
namespace {

struct VpnServer {
    const char* id;
    const char* country;
    const char* city;
    const char* flag;
    const char* ip;
    int  latency;
    int  load;
    bool streaming;
    bool gaming;
    bool secure_core;
};

static const VpnServer kServers[] = {
    {"ch-gen","Switzerland",  "Geneva",       u8"🇨🇭","185.107.81.247",  12, 23, true,  false, true },
    {"de-fra","Germany",      "Frankfurt",    u8"🇩🇪","89.187.164.12",   24, 45, true,  true,  false},
    {"nl-ams","Netherlands",  "Amsterdam",    u8"🇳🇱","136.243.87.201",  31, 67, true,  false, false},
    {"se-sto","Sweden",       "Stockholm",    u8"🇸🇪","193.138.218.64",  38, 28, false, false, true },
    {"gb-lon","United Kingdom","London",      u8"🇬🇧","217.138.218.45",  45, 71, true,  false, false},
    {"no-osl","Norway",       "Oslo",         u8"🇳🇴","92.119.148.55",   44, 19, false, false, true },
    {"is-rkv","Iceland",      "Reykjavik",    u8"🇮🇸","194.165.16.82",   52, 15, false, false, true },
    {"fr-par","France",       "Paris",        u8"🇫🇷","92.119.148.33",   41, 58, true,  false, false},
    {"us-nyc","United States","New York",     u8"🇺🇸","37.120.210.5",    89, 52, true,  true,  false},
    {"us-lax","United States","Los Angeles",  u8"🇺🇸","37.120.210.87",  102, 38, true,  true,  false},
    {"ca-tor","Canada",       "Toronto",      u8"🇨🇦","192.241.208.55",  95, 33, false, false, false},
    {"jp-tok","Japan",        "Tokyo",        u8"🇯🇵","149.22.30.18",   145, 29, true,  true,  false},
    {"sg-sin","Singapore",    "Singapore",    u8"🇸🇬","194.165.32.115", 134, 41, true,  false, false},
    {"au-syd","Australia",    "Sydney",       u8"🇦🇺","62.112.10.233",  178, 22, true,  false, false},
    {"br-sao","Brazil",       u8"São Paulo",  u8"🇧🇷","45.249.93.122",  162, 35, false, false, false},
};
static constexpr int kServerCount = static_cast<int>(sizeof(kServers)/sizeof(kServers[0]));

static const char* kProtocols[] = { "WireGuard", "OpenVPN", "IKEv2" };

// Design tokens
static const QColor kBg    { 0x12, 0x0B, 0x06 };
static const QColor kOrange{ 0xFF, 0x7A, 0x00 };
static const QColor kOr2   { 0xFF, 0x9B, 0x3D };
static const QColor kAccent{ 0xFF, 0xB7, 0x66 };
static const QColor kGreen { 0x4A, 0xDE, 0x80 };
static const QColor kWarn  { 0xFF, 0xB0, 0x20 };
static const QColor kRed   { 0xFF, 0x5A, 0x6A };
static const QColor kText  { 0xFF, 0xFF, 0xFF };
static const QColor kText2 { 0xC7, 0xB6, 0xA2 };
static const QColor kMuted { 0x6B, 0x5B, 0x4E };
static const QColor kDark  { 0x4A, 0x3B, 0x30 };

static inline QColor loadColor(int pct) {
    return pct < 40 ? kGreen : pct < 70 ? kWarn : kRed;
}
static inline QColor latColor(int ms) {
    return ms < 50 ? kGreen : ms < 100 ? kWarn : kRed;
}

// ─── Widget factory helpers ───────────────────────────────────────────────────
static QLabel* Lbl(const QString& t, int px, QColor c, QWidget* parent, bool bold = false) {
    auto* l = new QLabel(t, parent);
    QFont f = l->font();
    f.setPixelSize(px);
    f.setBold(bold);
    l->setFont(f);
    l->setStyleSheet(QString("color: %1; background: transparent; border: none;").arg(c.name()));
    return l;
}

static QFrame* HSep(QWidget* parent) {
    auto* f = new QFrame(parent);
    f->setFrameShape(QFrame::HLine);
    f->setStyleSheet("border: none; background: rgba(255,170,90,0.07);");
    f->setFixedHeight(1);
    return f;
}

static QWidget* MakeStatCard(const QString& title, QLabel*& val_out,
                              const QColor& vc, const QString& unit, QWidget* parent) {
    auto* card = new QWidget(parent);
    card->setStyleSheet(
        "QWidget { background: rgba(36,23,14,0.9);"
        "border: 1px solid rgba(255,170,90,0.1); border-radius: 12px; }");
    auto* col = new QVBoxLayout(card);
    col->setContentsMargins(14, 11, 14, 11);
    col->setSpacing(3);
    col->addWidget(Lbl(title, 10, kMuted, card));
    auto* row = new QHBoxLayout(); row->setSpacing(3);
    val_out = Lbl("—", 17, vc, card, true);
    row->addWidget(val_out);
    row->addWidget(Lbl(unit, 9, kMuted, card), 0, Qt::AlignBottom);
    row->addStretch();
    col->addLayout(row);
    return card;
}

// ─── Toggle switch helper ─────────────────────────────────────────────────────
static QWidget* MakeProtRow(const QString& label, const QString& desc,
                             bool checked, QWidget* parent,
                             std::function<void(bool)> cb = nullptr) {
    auto* row = new QWidget(parent);
    row->setStyleSheet("QWidget { background: transparent; border: none; }");
    auto* h = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(10);

    auto* txt = new QVBoxLayout(); txt->setSpacing(1);
    txt->addWidget(Lbl(label, 12, kText,  row, true));
    txt->addWidget(Lbl(desc,  10, kMuted, row));
    h->addLayout(txt, 1);

    auto* tog = new QPushButton(row);
    tog->setCheckable(true);
    tog->setChecked(checked);
    tog->setFixedSize(42, 23);
    tog->setCursor(Qt::PointingHandCursor);

    auto applyStyle = [tog](bool on) {
        tog->setStyleSheet(on
            ? "QPushButton{background:#FF7A00;border:1px solid rgba(255,122,0,0.4);border-radius:11px;}"
            : "QPushButton{background:rgba(255,255,255,0.07);"
              "border:1px solid rgba(255,170,90,0.12);border-radius:11px;}");
    };
    applyStyle(checked);

    auto* knob = new QWidget(tog);
    knob->setFixedSize(17, 17);
    knob->move(checked ? 21 : 3, 3);
    knob->setStyleSheet("background:white;border-radius:8px;");
    knob->setAttribute(Qt::WA_TransparentForMouseEvents);

    QObject::connect(tog, &QPushButton::toggled, tog,
        [applyStyle, knob, cb](bool on) {
            applyStyle(on);
            auto* a = new QPropertyAnimation(knob, "pos", knob);
            a->setDuration(150);
            a->setEasingCurve(QEasingCurve::OutBack);
            a->setEndValue(QPoint(on ? 21 : 3, 3));
            a->start(QAbstractAnimation::DeleteWhenStopped);
            if (cb) cb(on);
        });

    h->addWidget(tog, 0, Qt::AlignRight | Qt::AlignVCenter);
    return row;
}

// ─── Load progress bar ────────────────────────────────────────────────────────
class LoadBar final : public QWidget {
public:
    LoadBar(double v, QColor c, QWidget* p = nullptr) : QWidget(p), fill_(v), color_(c) {
        setFixedSize(44, 4);
    }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255,255,255,14));
        p.drawRoundedRect(rect(), 2, 2);
        const int w = static_cast<int>(width() * fill_);
        if (w > 0) { p.setBrush(color_); p.drawRoundedRect(QRect(0,0,w,height()), 2, 2); }
    }
private:
    double fill_; QColor color_;
};

// ─── VPN Status Orb ───────────────────────────────────────────────────────────
class VpnOrb final : public QWidget {
public:
    explicit VpnOrb(QWidget* parent = nullptr) : QWidget(parent) {
        setFixedSize(80, 80);
        timer_ = new QTimer(this);
        connect(timer_, &QTimer::timeout, this, [this]{ phase_ = fmod(phase_+0.04, 6.283); update(); });
        timer_->start(28);
    }
    void setState(int s) { state_ = s; update(); }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const QColor oc = state_ == 2 ? kGreen : state_ == 1 ? kOr2 : kDark;
        // Pulse rings
        if (state_ > 0) {
            for (int r = 0; r < 2; ++r) {
                const double t = fmod((phase_ + r*2.094) / 6.283, 1.0);
                const double ra = 30.0 + t*18.0;
                const double al = std::max(0.0, 0.45 - t*0.45);
                QPen pen(oc, 1.4);
                p.setPen(pen); p.setOpacity(al); p.setBrush(Qt::NoBrush);
                const int ri = static_cast<int>(ra);
                p.drawEllipse(40-ri, 40-ri, ri*2, ri*2);
                p.setOpacity(1.0);
            }
        }
        // Core circle
        const int r = 30;
        QColor bg = oc; bg.setAlpha(state_==2?25:state_==1?18:13);
        p.setBrush(bg); QColor bd=oc; bd.setAlpha(48); p.setPen(QPen(bd,1.5));
        p.drawEllipse(40-r, 40-r, r*2, r*2);
        // Icon
        p.setPen(Qt::NoPen);
        if (state_ == 2) {
            QPen ck(kGreen, 2.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
            p.setPen(ck); p.drawLine(33,41,38,46); p.drawLine(38,46,48,34);
        } else if (state_ == 1) {
            double ang = phase_*180.0/3.14159;
            QPen arc(kOr2, 2.5, Qt::SolidLine, Qt::RoundCap);
            p.setPen(arc);
            p.drawArc(QRect(34,34,12,12), (int)(ang*16), 200*16);
        } else {
            p.setPen(QPen(kDark, 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            QPolygon tri({QPoint(40,31),QPoint(31,49),QPoint(49,49)});
            p.drawPolyline(tri);
            p.drawLine(40,36,40,42); p.drawPoint(40,45);
        }
    }
private:
    QTimer* timer_; double phase_=0.0; int state_=0;
};

} // namespace

// ─── Helpers ──────────────────────────────────────────────────────────────────
static QString FmtDur(int secs) {
    return QString("%1:%2:%3")
        .arg(secs/3600, 2, 10, QChar('0'))
        .arg((secs%3600)/60, 2, 10, QChar('0'))
        .arg(secs%60, 2, 10, QChar('0'));
}
static QString RandSpeed(double base, double var) {
    const double v = base + (static_cast<double>(rand()%1000)/1000.0)*var;
    return v>=1000 ? QString::number(v/1000.0,'f',1)+" GB/s"
                   : QString::number(v,'f',1)+" MB/s";
}

// ─── Build VPN Page ───────────────────────────────────────────────────────────
QWidget* MainWindow::BuildVpnPage() {
    auto* page = new QWidget();
    page->setStyleSheet(QString("QWidget#VpnPage{background:%1;}").arg(kBg.name()));
    page->setObjectName("VpnPage");

    auto* root = new QHBoxLayout(page);
    root->setContentsMargins(20, 20, 20, 20);
    root->setSpacing(16);

    // ══════════════════════════════════ CENTER ════════════════════════════════
    auto* center = new QVBoxLayout(); center->setSpacing(14);

    // ── Hero card ─────────────────────────────────────────────────────────────
    auto* hero = new QWidget(page);
    hero->setObjectName("VpnHero");
    hero->setStyleSheet(
        "QWidget#VpnHero{"
        "background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
        "  stop:0 rgba(36,23,14,0.99),stop:1 rgba(24,14,6,1.0));"
        "border:1px solid rgba(255,170,90,0.1);border-radius:20px;}");

    auto* hero_h = new QHBoxLayout(hero);
    hero_h->setContentsMargins(24, 22, 24, 22);
    hero_h->setSpacing(20);

    // Orb
    vpn_orb_widget_ = new VpnOrb(hero);
    static_cast<VpnOrb*>(vpn_orb_widget_)->setState(0);
    hero_h->addWidget(vpn_orb_widget_, 0, Qt::AlignVCenter);

    // Info
    auto* info = new QVBoxLayout(); info->setSpacing(3);
    vpn_state_label_  = Lbl("Not Protected",     13, kDark, hero, true);
    vpn_server_label_ = Lbl("No server selected",20, kText, hero, true);
    vpn_ip_label_     = Lbl("",                  11, kMuted,hero);
    vpn_meta_label_   = Lbl("Your traffic is not encrypted", 11, kDark, hero);
    vpn_duration_label_= Lbl("",                 11, kMuted,hero);
    QFont mono = vpn_ip_label_->font();
    mono.setFamily("Consolas, monospace");
    vpn_ip_label_->setFont(mono);
    vpn_duration_label_->setFont(mono);

    // Protocol selector
    auto* proto_row = new QHBoxLayout(); proto_row->setSpacing(6);
    for (int i = 0; i < 3; ++i) {
        auto* pb = new QPushButton(kProtocols[i], hero);
        pb->setCursor(Qt::PointingHandCursor);
        pb->setFixedHeight(24);
        pb->setProperty("proto_i", i);
        pb->setObjectName("VpnProtoBtn");
        auto applyProtoStyle = [pb](bool on){
            pb->setStyleSheet(on
                ? "QPushButton{background:rgba(255,122,0,0.12);border:1px solid rgba(255,122,0,0.24);"
                  "color:#FF9B3D;font-size:11px;font-weight:700;border-radius:12px;padding:0 10px;}"
                  "QPushButton:hover{background:rgba(255,122,0,0.2);}"
                : "QPushButton{background:transparent;border:1px solid rgba(255,170,90,0.08);"
                  "color:#8B7355;font-size:11px;border-radius:12px;padding:0 10px;}"
                  "QPushButton:hover{color:#C7B6A2;border-color:rgba(255,170,90,0.18);}");
        };
        applyProtoStyle(i == 0);
        connect(pb, &QPushButton::clicked, this, [this, i, hero] {
            vpn_protocol_ = i;
            const auto btns = hero->findChildren<QPushButton*>("VpnProtoBtn");
            for (auto* b : btns) {
                const int bi = b->property("proto_i").toInt();
                b->setStyleSheet(bi == i
                    ? "QPushButton{background:rgba(255,122,0,0.12);border:1px solid rgba(255,122,0,0.24);"
                      "color:#FF9B3D;font-size:11px;font-weight:700;border-radius:12px;padding:0 10px;}"
                      "QPushButton:hover{background:rgba(255,122,0,0.2);}"
                    : "QPushButton{background:transparent;border:1px solid rgba(255,170,90,0.08);"
                      "color:#8B7355;font-size:11px;border-radius:12px;padding:0 10px;}"
                      "QPushButton:hover{color:#C7B6A2;border-color:rgba(255,170,90,0.18);}");
            }
        });
        proto_row->addWidget(pb);
    }
    proto_row->addStretch();

    info->addWidget(vpn_state_label_);
    info->addWidget(vpn_server_label_);
    info->addWidget(vpn_ip_label_);
    info->addWidget(vpn_meta_label_);
    info->addWidget(vpn_duration_label_);
    info->addLayout(proto_row);
    hero_h->addLayout(info, 1);

    // Connect button
    vpn_connect_btn_ = new QPushButton("Connect", hero);
    vpn_connect_btn_->setFixedSize(132, 48);
    vpn_connect_btn_->setCursor(Qt::PointingHandCursor);
    vpn_connect_btn_->setStyleSheet(
        "QPushButton{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #FF7A00,stop:1 #FF7A00);"
        "color:white;border:none;border-radius:14px;font-size:14px;font-weight:700;}"
        "QPushButton:hover{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #FF7A00,stop:1 #FF7A00);}"
        "QPushButton:pressed{background:#FF7A00;}");
    connect(vpn_connect_btn_, &QPushButton::clicked, this, &MainWindow::VpnToggleConnect);
    hero_h->addWidget(vpn_connect_btn_, 0, Qt::AlignVCenter);

    center->addWidget(hero);

    // ── Server Browser ────────────────────────────────────────────────────────
    auto* browser = new QWidget(page);
    browser->setObjectName("VpnBrowser");
    browser->setStyleSheet(
        "QWidget#VpnBrowser{background:rgba(26,18,12,0.85);"
        "border:1px solid rgba(255,170,90,0.08);border-radius:16px;}");

    auto* blay = new QVBoxLayout(browser);
    blay->setContentsMargins(16, 14, 16, 14);
    blay->setSpacing(10);

    // Quick connect
    {
        auto* qc_lbl = Lbl("Quick Connect", 10, kMuted, browser, true);
        blay->addWidget(qc_lbl);
        auto* qr = new QHBoxLayout(); qr->setSpacing(8);
        struct QCE { const char* label; int idx; };
        const QCE qcs[] = {{"⚡ Recommended",0},{"📶 Fastest",1},{"📡 Nearest",3}};
        for (const auto& q : qcs) {
            auto* btn = new QPushButton(browser);
            btn->setCursor(Qt::PointingHandCursor);
            btn->setFixedHeight(50);
            btn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            btn->setStyleSheet(
                "QPushButton{background:rgba(26,18,12,0.9);border:1px solid rgba(255,170,90,0.1);"
                "border-radius:12px;text-align:left;}"
                "QPushButton:hover{border-color:rgba(255,122,0,0.25);background:rgba(36,23,14,0.95);}");
            auto* ql = new QVBoxLayout(btn);
            ql->setContentsMargins(12,8,12,8); ql->setSpacing(2);
            ql->addWidget(Lbl(q.label, 11, kText, btn, true));
            ql->addWidget(Lbl(
                QString::fromUtf8(kServers[q.idx].flag) + " " + kServers[q.idx].city,
                10, kMuted, btn));
            const int si = q.idx;
            connect(btn, &QPushButton::clicked, this, [this, si]{
                VpnSelectServer(si); VpnToggleConnect();
            });
            qr->addWidget(btn);
        }
        blay->addLayout(qr);
    }

    blay->addWidget(HSep(browser));

    // Search
    vpn_search_edit_ = new QLineEdit(browser);
    vpn_search_edit_->setPlaceholderText("Search countries, cities…");
    vpn_search_edit_->setFixedHeight(38);
    vpn_search_edit_->setStyleSheet(
        "QLineEdit{background:rgba(26,18,12,0.9);border:1px solid rgba(255,170,90,0.1);"
        "border-radius:10px;color:#C7B6A2;font-size:12px;padding:0 12px;}"
        "QLineEdit:focus{border-color:rgba(255,122,0,0.28);}");
    blay->addWidget(vpn_search_edit_);

    // Filter tabs
    {
        auto* fr = new QHBoxLayout(); fr->setSpacing(6);
        const char* fnames[] = {"All","Favorites","Streaming","Gaming","Secure Core"};
        for (int fi = 0; fi < 5; ++fi) {
            auto* fb = new QPushButton(fnames[fi], browser);
            fb->setCursor(Qt::PointingHandCursor);
            fb->setFixedHeight(26);
            fb->setProperty("fi", fi);
            fb->setObjectName("VpnFilter");
            fb->setStyleSheet(fi==0
                ? "QPushButton{background:rgba(255,122,0,0.12);border:1px solid rgba(255,122,0,0.22);"
                  "color:#FF9B3D;font-size:11px;font-weight:700;border-radius:13px;padding:0 12px;}"
                : "QPushButton{background:transparent;border:1px solid rgba(255,170,90,0.08);"
                  "color:#8B7355;font-size:11px;border-radius:13px;padding:0 12px;}"
                  "QPushButton:hover{color:#C7B6A2;border-color:rgba(255,170,90,0.18);}");
            connect(fb, &QPushButton::clicked, this, [this, fi, browser] {
                vpn_filter_mode_ = fi;
                const auto all = browser->findChildren<QPushButton*>("VpnFilter");
                for (auto* b : all) {
                    const int bi = b->property("fi").toInt();
                    b->setStyleSheet(bi==fi
                        ? "QPushButton{background:rgba(255,122,0,0.12);border:1px solid rgba(255,122,0,0.22);"
                          "color:#FF9B3D;font-size:11px;font-weight:700;border-radius:13px;padding:0 12px;}"
                        : "QPushButton{background:transparent;border:1px solid rgba(255,170,90,0.08);"
                          "color:#8B7355;font-size:11px;border-radius:13px;padding:0 12px;}"
                          "QPushButton:hover{color:#C7B6A2;border-color:rgba(255,170,90,0.18);}");
                }
                VpnRefreshServerList(vpn_search_edit_->text());
            });
            fr->addWidget(fb);
        }
        fr->addStretch();
        blay->addLayout(fr);
    }

    // Server list (scrollable)
    auto* scroll = new QScrollArea(browser);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setStyleSheet(
        "QScrollArea{background:transparent;border:none;}"
        "QScrollBar:vertical{width:4px;background:transparent;}"
        "QScrollBar::handle:vertical{background:rgba(255,170,90,0.15);border-radius:2px;}"
        "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}");
    vpn_server_list_ = new QWidget();
    vpn_server_list_->setStyleSheet("background:transparent;");
    scroll->setWidget(vpn_server_list_);
    scroll->setWidgetResizable(true);
    scroll->setMinimumHeight(220);
    blay->addWidget(scroll);

    center->addWidget(browser, 1);
    root->addLayout(center, 6);

    // ══════════════════════════════════ RIGHT ═════════════════════════════════
    auto* right = new QVBoxLayout(); right->setSpacing(12);

    // Stats card
    {
        auto* card = new QWidget(page);
        card->setStyleSheet(
            "QWidget{background:rgba(26,18,12,0.85);"
            "border:1px solid rgba(255,170,90,0.08);border-radius:16px;}");
        auto* lay = new QVBoxLayout(card);
        lay->setContentsMargins(14,14,14,14); lay->setSpacing(10);
        lay->addWidget(Lbl("Connection Stats", 11, kText2, card, true));

        auto* r1 = new QHBoxLayout(); r1->setSpacing(8);
        auto* r2 = new QHBoxLayout(); r2->setSpacing(8);
        r1->addWidget(MakeStatCard("Download", vpn_dl_label_,  kGreen,  "MB/s", card));
        r1->addWidget(MakeStatCard("Upload",   vpn_ul_label_,  kOr2,    "MB/s", card));
        r2->addWidget(MakeStatCard("Latency",  vpn_lat_label_, kAccent, "ms",   card));
        r2->addWidget(MakeStatCard("Bandwidth",vpn_bw_label_,  kText2,  "total",card));
        lay->addLayout(r1); lay->addLayout(r2);
        right->addWidget(card);
    }

    // Protection panel
    {
        auto* card = new QWidget(page);
        card->setStyleSheet(
            "QWidget{background:rgba(26,18,12,0.85);"
            "border:1px solid rgba(255,170,90,0.08);border-radius:16px;}");
        auto* lay = new QVBoxLayout(card);
        lay->setContentsMargins(14,14,14,14); lay->setSpacing(10);
        lay->addWidget(Lbl("Protection", 11, kText2, card, true));

        struct P { const char* n; const char* d; bool on; };
        const P rows[] = {
            {"Kill Switch",    "Block traffic if VPN drops",       true },
            {"DNS Protection", "Prevent DNS leaks",                true },
            {"Tracker Block",  "Block trackers & malicious sites", false},
            {"Auto Connect",   "Connect on startup",               false},
        };
        for (const auto& r : rows) {
            lay->addWidget(MakeProtRow(r.n, r.d, r.on, card));
            lay->addWidget(HSep(card));
        }
        right->addWidget(card);
    }

    // Advanced settings
    {
        auto* card = new QWidget(page);
        card->setStyleSheet(
            "QWidget{background:rgba(26,18,12,0.85);"
            "border:1px solid rgba(255,170,90,0.08);border-radius:16px;}");
        auto* lay = new QVBoxLayout(card);
        lay->setContentsMargins(14,14,14,14); lay->setSpacing(10);
        lay->addWidget(Lbl("Advanced", 11, kText2, card, true));

        struct A { const char* n; const char* d; bool on; };
        const A arows[] = {
            {"Split Tunnel",    "Route only selected apps",  false},
            {"Custom DNS",      "Use custom DNS servers",    false},
            {"Startup Connect", "Auto-connect on login",     false},
            {"Auto Protocol",   "Let VPN pick best protocol",true },
        };
        for (const auto& a : arows) {
            lay->addWidget(MakeProtRow(a.n, a.d, a.on, card));
            lay->addWidget(HSep(card));
        }
        right->addWidget(card);
    }

    right->addStretch();
    root->addLayout(right, 4);

    // ── Wire up ───────────────────────────────────────────────────────────────
    connect(vpn_search_edit_, &QLineEdit::textChanged,
            this, &MainWindow::VpnRefreshServerList);

    // Tick timer (connection duration)
    vpn_tick_timer_ = new QTimer(this);
    connect(vpn_tick_timer_, &QTimer::timeout, this, [this]{
        ++vpn_connection_secs_;
        if (vpn_duration_label_)
            vpn_duration_label_->setText(FmtDur(vpn_connection_secs_));
    });

    // Stats update timer
    vpn_stats_timer_ = new QTimer(this);
    connect(vpn_stats_timer_, &QTimer::timeout, this, [this]{
        if (vpn_state_ != VpnState::Connected) return;
        if (vpn_dl_label_)  vpn_dl_label_->setText(RandSpeed(45, 80));
        if (vpn_ul_label_)  vpn_ul_label_->setText(RandSpeed(5, 20));
        const int jitter = (rand()%7)-3;
        const int lat = kServers[vpn_selected_server_].latency;
        if (vpn_lat_label_) vpn_lat_label_->setText(QString::number(lat+jitter)+" ms");
        if (vpn_bw_label_)  vpn_bw_label_->setText("2.4 GB");
    });
    vpn_stats_timer_->start(1100);

    // Initial populate
    VpnSelectServer(0);
    VpnRefreshServerList();
    VpnUpdateHero();

    return page;
}

// ─── VPN Logic ────────────────────────────────────────────────────────────────
void MainWindow::VpnToggleConnect() {
    switch (vpn_state_) {
    case VpnState::Disconnected:
        vpn_state_ = VpnState::Connecting;
        VpnUpdateHero();
        QTimer::singleShot(2500, this, [this]{
            if (vpn_state_ == VpnState::Connecting) {
                vpn_state_ = VpnState::Connected;
                vpn_connection_secs_ = 0;
                vpn_tick_timer_->start(1000);
                VpnUpdateHero();
            }
        });
        break;
    case VpnState::Connected:
        vpn_state_ = VpnState::Disconnecting;
        vpn_tick_timer_->stop();
        VpnUpdateHero();
        QTimer::singleShot(900, this, [this]{
            if (vpn_state_ == VpnState::Disconnecting) {
                vpn_state_ = VpnState::Disconnected;
                VpnUpdateHero();
            }
        });
        break;
    default:
        vpn_state_ = VpnState::Disconnected;
        vpn_tick_timer_->stop();
        VpnUpdateHero();
        break;
    }
}

void MainWindow::VpnSelectServer(int idx) {
    if (idx < 0 || idx >= kServerCount) return;
    vpn_selected_server_ = idx;
    VpnRefreshServerList(vpn_search_edit_ ? vpn_search_edit_->text() : QString{});
}

void MainWindow::VpnUpdateHero() {
    const VpnServer& s = kServers[vpn_selected_server_];
    const bool connecting   = (vpn_state_ == VpnState::Connecting ||
                               vpn_state_ == VpnState::Disconnecting);
    const bool connected    = (vpn_state_ == VpnState::Connected);
    const bool disconnected = (vpn_state_ == VpnState::Disconnected);

    // Orb
    if (vpn_orb_widget_)
        static_cast<VpnOrb*>(vpn_orb_widget_)->setState(
            connected ? 2 : connecting ? 1 : 0);

    // State label
    if (vpn_state_label_) {
        const char* txt  = connected    ? "Connected"
                         : vpn_state_ == VpnState::Connecting    ? "Connecting\xe2\x80\xa6"
                         : vpn_state_ == VpnState::Disconnecting ? "Disconnecting\xe2\x80\xa6"
                         : "Not Protected";
        const QColor col = connected ? kGreen : connecting ? kOr2 : kDark;
        vpn_state_label_->setText(txt);
        vpn_state_label_->setStyleSheet(
            QString("color:%1;font-weight:700;font-size:13px;"
                    "background:transparent;border:none;").arg(col.name()));
    }

    // Server / hero text
    if (vpn_server_label_) {
        vpn_server_label_->setText(disconnected
            ? "No server selected"
            : QString::fromUtf8(s.flag) + " " + QString::fromUtf8(s.country)
              + "  \xc2\xb7  " + QString::fromUtf8(s.city));
    }
    if (vpn_ip_label_)
        vpn_ip_label_->setText(connected ? QString::fromLatin1(s.ip) : "");
    if (vpn_meta_label_)
        vpn_meta_label_->setText(connected
            ? QString("%1  |  %2 ms").arg(kProtocols[vpn_protocol_]).arg(s.latency)
            : connecting ? "Establishing secure tunnel\xe2\x80\xa6"
            : "Your traffic is not encrypted");
    if (vpn_duration_label_)
        vpn_duration_label_->setText(connected ? FmtDur(vpn_connection_secs_) : "");

    // Connect button
    if (vpn_connect_btn_) {
        vpn_connect_btn_->setText(
            connected   ? "Disconnect"
            : connecting? "Cancel"
            :             "Connect");
        if (connected)
            vpn_connect_btn_->setStyleSheet(
                "QPushButton{background:rgba(255,90,106,0.14);color:#FF5A6A;"
                "border:1px solid rgba(255,90,106,0.22);border-radius:14px;"
                "font-size:14px;font-weight:700;}"
                "QPushButton:hover{background:rgba(255,90,106,0.22);}");
        else if (connecting)
            vpn_connect_btn_->setStyleSheet(
                "QPushButton{background:rgba(255,155,61,0.12);color:#FF9B3D;"
                "border:1px solid rgba(255,155,61,0.2);border-radius:14px;"
                "font-size:14px;font-weight:700;}"
                "QPushButton:hover{background:rgba(255,155,61,0.22);}");
        else
            vpn_connect_btn_->setStyleSheet(
                "QPushButton{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
                "stop:0 #FF7A00,stop:1 #FF7A00);"
                "color:white;border:none;border-radius:14px;"
                "font-size:14px;font-weight:700;}"
                "QPushButton:hover{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,"
                "stop:0 #FF7A00,stop:1 #FF7A00);}"
                "QPushButton:pressed{background:#FF7A00;}");
    }

    // Reset stats when disconnecting
    if (disconnected) {
        if (vpn_dl_label_)  vpn_dl_label_->setText("—");
        if (vpn_ul_label_)  vpn_ul_label_->setText("—");
        if (vpn_lat_label_) vpn_lat_label_->setText("—");
        if (vpn_bw_label_)  vpn_bw_label_->setText("—");
    }
}

void MainWindow::VpnRefreshServerList(const QString& search) {
    if (!vpn_server_list_) return;

    // Clear
    if (auto* old = vpn_server_list_->layout()) {
        QLayoutItem* item;
        while ((item = old->takeAt(0)) != nullptr) {
            if (item->widget()) item->widget()->deleteLater();
            delete item;
        }
        delete old;
    }

    auto* vbox = new QVBoxLayout(vpn_server_list_);
    vbox->setContentsMargins(0,0,0,0); vbox->setSpacing(2);

    const QString q = search.toLower();
    int shown = 0;
    for (int i = 0; i < kServerCount; ++i) {
        const VpnServer& sv = kServers[i];
        const bool is_fav = (std::find(vpn_favorites_.begin(), vpn_favorites_.end(), i) != vpn_favorites_.end());

        if (vpn_filter_mode_ == 1 && !is_fav)        continue;
        if (vpn_filter_mode_ == 2 && !sv.streaming)  continue;
        if (vpn_filter_mode_ == 3 && !sv.gaming)     continue;
        if (vpn_filter_mode_ == 4 && !sv.secure_core)continue;
        if (!q.isEmpty()) {
            if (!QString::fromUtf8(sv.country).toLower().contains(q) &&
                !QString::fromUtf8(sv.city).toLower().contains(q))
                continue;
        }

        const bool active = (i == vpn_selected_server_);

        auto* row = new QWidget(vpn_server_list_);
        row->setCursor(Qt::PointingHandCursor);
        row->setStyleSheet(active
            ? "QWidget{background:rgba(255,122,0,0.08);"
              "border:1px solid rgba(255,122,0,0.18);border-radius:12px;}"
            : "QWidget{background:transparent;border:1px solid transparent;border-radius:12px;}"
              "QWidget:hover{background:rgba(255,255,255,0.024);}");

        auto* rh = new QHBoxLayout(row);
        rh->setContentsMargins(12,9,10,9); rh->setSpacing(10);

        // Flag
        rh->addWidget(Lbl(QString::fromUtf8(sv.flag), 20, kText, row));

        // Country + badges
        auto* nc = new QVBoxLayout(); nc->setSpacing(3);
        nc->addWidget(Lbl(
            QString::fromUtf8(sv.country) + "  " + QString::fromUtf8(sv.city),
            12, active ? kOr2 : kText, row, true));
        auto* badges = new QHBoxLayout(); badges->setSpacing(4);
        if (sv.secure_core) {
            auto* b = Lbl(u8"🔒 Secure Core", 9, kOr2, row);
            b->setStyleSheet("color:#FF9B3D;background:rgba(255,155,61,0.1);"
                             "border:1px solid rgba(255,155,61,0.18);"
                             "border-radius:5px;padding:1px 5px;");
            badges->addWidget(b);
        }
        if (sv.streaming) {
            auto* b = Lbl(u8"📺 Stream", 9, kText2, row);
            b->setStyleSheet("color:#C7B6A2;background:rgba(199,182,162,0.07);"
                             "border:1px solid rgba(199,182,162,0.14);"
                             "border-radius:5px;padding:1px 5px;");
            badges->addWidget(b);
        }
        if (sv.gaming) {
            auto* b = Lbl(u8"🎮 Gaming", 9, kText2, row);
            b->setStyleSheet("color:#C7B6A2;background:rgba(199,182,162,0.07);"
                             "border:1px solid rgba(199,182,162,0.14);"
                             "border-radius:5px;padding:1px 5px;");
            badges->addWidget(b);
        }
        badges->addStretch();
        nc->addLayout(badges);
        rh->addLayout(nc, 1);

        // Latency
        const QColor lc = latColor(sv.latency);
        auto* lat_lbl = Lbl(QString::number(sv.latency)+" ms", 11, lc, row, true);
        lat_lbl->setStyleSheet(
            QString("color:%1;font-family:'Consolas',monospace;"
                    "background:transparent;border:none;").arg(lc.name()));
        rh->addWidget(lat_lbl);

        // Load
        auto* ldc = new QVBoxLayout(); ldc->setSpacing(3); ldc->setAlignment(Qt::AlignRight);
        const QColor ldc_col = loadColor(sv.load);
        auto* lp = Lbl(QString::number(sv.load)+"%", 9, ldc_col, row);
        lp->setStyleSheet(
            QString("color:%1;font-family:'Consolas',monospace;"
                    "background:transparent;border:none;").arg(ldc_col.name()));
        lp->setAlignment(Qt::AlignRight);
        ldc->addWidget(lp);
        ldc->addWidget(new LoadBar(sv.load/100.0, ldc_col, row));
        rh->addLayout(ldc);

        // Favorite
        auto* fav_btn = new QPushButton(is_fav ? "★" : "☆", row);
        fav_btn->setFixedSize(24, 24);
        fav_btn->setCursor(Qt::PointingHandCursor);
        fav_btn->setStyleSheet(is_fav
            ? "QPushButton{background:none;border:none;color:#FF9B3D;font-size:14px;}"
            : "QPushButton{background:none;border:none;color:#33261A;font-size:14px;}"
              "QPushButton:hover{color:#C7B6A2;}");
        const int si = i;
        connect(fav_btn, &QPushButton::clicked, this, [this, si]{
            auto it = std::find(vpn_favorites_.begin(), vpn_favorites_.end(), si);
            if (it != vpn_favorites_.end()) vpn_favorites_.erase(it);
            else vpn_favorites_.push_back(si);
            VpnRefreshServerList(vpn_search_edit_ ? vpn_search_edit_->text() : QString{});
        });
        rh->addWidget(fav_btn);

        // Click row to select server
        row->installEventFilter(this);
        row->setProperty("vpn_srv", si);

        vbox->addWidget(row);
        ++shown;
    }

    if (shown == 0) {
        auto* empty = Lbl("No servers match your search", 12, kMuted, vpn_server_list_);
        empty->setAlignment(Qt::AlignCenter);
        empty->setFixedHeight(60);
        vbox->addWidget(empty);
    }
    vbox->addStretch();
}

bool MainWindow::eventFilter(QObject* obj, QEvent* event) {
    if (event->type() == QEvent::MouseButtonRelease) {
        auto* widget = qobject_cast<QWidget*>(obj);
        if (widget) {
            const QVariant vpn_prop = widget->property("vpn_srv");
            if (vpn_prop.isValid()) {
                VpnSelectServer(vpn_prop.toInt());
                return false;
            }
        }
    }
    return QMainWindow::eventFilter(obj, event);
}

} // namespace avdashboard
