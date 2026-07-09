// main_window_settings.cpp — redesigned Settings/Config page (Figma dark-orange theme)
#include "main_window.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <memory>

namespace avdashboard {

namespace {

// ────────────────────────────────────────────────────────────────────────────
// SettingsIcon — QPainter icon renderer (same style as HistIcon)
// ────────────────────────────────────────────────────────────────────────────
class SettingsIcon : public QWidget {
public:
    enum class Type { Shield, FolderSearch, Cpu, Bot, Lock, Save, Eye, FolderOpen, Plus, Minus };

    SettingsIcon(Type t, int sz, QWidget* parent = nullptr)
        : QWidget(parent), type_(t), sz_(sz) {
        setFixedSize(sz, sz);
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const double s = sz_ / 24.0;
        p.setPen(QPen(color_, 1.65 * s, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.setBrush(Qt::NoBrush);
        switch (type_) {
        case Type::Shield: {
            QPainterPath path;
            path.moveTo(12*s, 2*s);
            path.lineTo(20*s, 6*s);
            path.lineTo(20*s, 12*s);
            path.quadTo(20*s, 18*s, 12*s, 22*s);
            path.quadTo(4*s, 18*s, 4*s, 12*s);
            path.lineTo(4*s, 6*s);
            path.closeSubpath();
            p.drawPath(path);
            p.drawLine(QPointF(12*s,7*s), QPointF(12*s,13*s));
            p.drawPoint(QPointF(12*s,16*s));
            break;
        }
        case Type::FolderSearch: {
            QPainterPath folder;
            folder.moveTo(3*s, 7*s);
            folder.lineTo(3*s, 19*s);
            folder.lineTo(21*s, 19*s);
            folder.lineTo(21*s, 9*s);
            folder.lineTo(11*s, 9*s);
            folder.lineTo(9*s, 7*s);
            folder.closeSubpath();
            p.drawPath(folder);
            p.drawEllipse(QRectF(10*s, 11*s, 5*s, 5*s));
            p.drawLine(QPointF(14.5*s, 15.5*s), QPointF(17*s, 18*s));
            break;
        }
        case Type::Cpu: {
            p.drawRect(QRectF(7*s, 7*s, 10*s, 10*s));
            for (int i = 0; i < 3; ++i) {
                double y = (9.5 + 2.5*i)*s;
                p.drawLine(QPointF(3*s, y), QPointF(7*s, y));
                p.drawLine(QPointF(17*s, y), QPointF(21*s, y));
            }
            for (int i = 0; i < 3; ++i) {
                double x = (9.5 + 2.5*i)*s;
                p.drawLine(QPointF(x, 3*s), QPointF(x, 7*s));
                p.drawLine(QPointF(x, 17*s), QPointF(x, 21*s));
            }
            break;
        }
        case Type::Bot: {
            p.drawEllipse(QRectF(9*s, 2*s, 6*s, 4*s));
            p.drawLine(QPointF(12*s, 6*s), QPointF(12*s, 8*s));
            QPainterPath body;
            body.addRoundedRect(QRectF(4*s, 8*s, 16*s, 12*s), 3*s, 3*s);
            p.drawPath(body);
            p.drawEllipse(QRectF(8*s, 12*s, 3*s, 3*s));
            p.drawEllipse(QRectF(13*s, 12*s, 3*s, 3*s));
            p.drawLine(QPointF(2*s, 13*s), QPointF(4*s, 13*s));
            p.drawLine(QPointF(20*s, 13*s), QPointF(22*s, 13*s));
            break;
        }
        case Type::Lock: {
            QPainterPath shackle;
            shackle.moveTo(8*s, 11*s);
            shackle.lineTo(8*s, 8*s);
            shackle.quadTo(8*s, 4*s, 12*s, 4*s);
            shackle.quadTo(16*s, 4*s, 16*s, 8*s);
            shackle.lineTo(16*s, 11*s);
            p.drawPath(shackle);
            QPainterPath body;
            body.addRoundedRect(QRectF(5*s, 11*s, 14*s, 10*s), 2*s, 2*s);
            p.drawPath(body);
            p.drawEllipse(QRectF(10.5*s, 14.5*s, 3*s, 3*s));
            break;
        }
        case Type::Save: {
            p.drawRoundedRect(QRectF(3*s, 3*s, 18*s, 18*s), 2*s, 2*s);
            p.drawRect(QRectF(8*s, 3*s, 8*s, 7*s));
            p.drawRect(QRectF(5*s, 13*s, 14*s, 8*s));
            break;
        }
        case Type::Eye: {
            QPainterPath ep;
            ep.moveTo(2*s, 12*s);
            ep.quadTo(12*s, 4*s, 22*s, 12*s);
            ep.quadTo(12*s, 20*s, 2*s, 12*s);
            p.drawPath(ep);
            p.drawEllipse(QRectF(9*s, 9*s, 6*s, 6*s));
            break;
        }
        case Type::FolderOpen: {
            QPainterPath fp;
            fp.moveTo(3*s, 8*s);
            fp.lineTo(3*s, 19*s);
            fp.lineTo(21*s, 19*s);
            fp.lineTo(21*s, 10*s);
            fp.lineTo(9*s, 10*s);
            fp.lineTo(7*s, 8*s);
            fp.closeSubpath();
            p.drawPath(fp);
            p.drawLine(QPointF(9*s, 6*s), QPointF(21*s, 6*s));
            break;
        }
        case Type::Plus:
            p.drawLine(QPointF(12*s, 5*s), QPointF(12*s, 19*s));
            p.drawLine(QPointF(5*s, 12*s), QPointF(19*s, 12*s));
            break;
        case Type::Minus:
            p.drawLine(QPointF(5*s, 12*s), QPointF(19*s, 12*s));
            break;
        }
    }

public:
    QColor color_ = QColor(0xFF, 0x7A, 0x00);
    Type   type_;
    int    sz_;
};

// ────────────────────────────────────────────────────────────────────────────
// Label/form helpers
// ────────────────────────────────────────────────────────────────────────────
static QLabel* makeFormLabel(const QString& text, QWidget* parent) {
    auto* lbl = new QLabel(text, parent);
    lbl->setStyleSheet("color:#C7B6A2; font-size:9.5pt; background:transparent;");
    lbl->setMinimumWidth(130);
    return lbl;
}

static const char* kLineEditStyle =
    "QLineEdit { background:#120B06; border:1px solid rgba(255,170,90,46);"
    " border-radius:8px; padding:6px 12px; color:#ffffff; font-size:10pt; }"
    "QLineEdit:focus { border-color:rgba(255,122,0,120); }";

static const char* kComboStyle =
    "QComboBox { background:#1A120C; border:1px solid rgba(255,170,90,46);"
    " border-radius:8px; padding:4px 12px; color:#E8D5C0; font-size:10pt; min-width:140px; }"
    "QComboBox::drop-down { border:none; }"
    "QComboBox QAbstractItemView { background:#1A120C; color:#E8D5C0;"
    " selection-background-color:rgba(255,122,0,38); border:1px solid rgba(255,170,90,46); }";

static const char* kSpinStyle =
    "QSpinBox { background:#120B06; border:1px solid rgba(255,170,90,46);"
    " border-radius:8px; padding:4px 8px; color:#E8D5C0; font-size:10pt; }";

static const char* kCheckStyle =
    "QCheckBox { color:#E8D5C0; font-size:10pt; spacing:8px; }"
    "QCheckBox::indicator { width:18px; height:18px; border:1px solid rgba(255,170,90,46);"
    " border-radius:4px; background:#120B06; }"
    "QCheckBox::indicator:checked { background:#FF7A00; border-color:#FF7A00; }";

static const char* kListStyle =
    "QListWidget { background:#1A120C; border:1px solid rgba(255,170,90,26);"
    " border-radius:8px; color:#E8D5C0; font-size:10pt; }"
    "QListWidget::item { padding:6px 10px; border-bottom:1px solid rgba(255,170,90,12); }"
    "QListWidget::item:selected { background:rgba(255,122,0,38); color:#fff; }";

static const char* kSaveBtnStyle =
    "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #CC5500);"
    " border:none; border-radius:10px; color:#fff; font-size:10.5pt; font-weight:700;"
    " padding:10px 32px; }"
    "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9030,stop:1 #DD6600); }";

static const char* kSmallBtnStyle =
    "QPushButton { background:rgba(255,122,0,22); border:1px solid rgba(255,122,0,60);"
    " border-radius:8px; color:#FF9B3D; font-size:9.5pt; padding:5px 14px; }"
    "QPushButton:hover { background:rgba(255,122,0,40); }";

static const char* kDangerBtnStyle =
    "QPushButton { background:rgba(255,90,106,18); border:1px solid rgba(255,90,106,60);"
    " border-radius:8px; color:#FF5A6A; font-size:9.5pt; padding:5px 14px; }"
    "QPushButton:hover { background:rgba(255,90,106,36); }";

// Create a dark card with title
static QPair<QFrame*, QVBoxLayout*> makeCard(const QString& title, QWidget* parent) {
    auto* card = new QFrame(parent);
    card->setStyleSheet(
        "QFrame { background:#1A120C; border:1px solid rgba(255,170,90,26); border-radius:12px; }");
    auto* cl = new QVBoxLayout(card);
    cl->setContentsMargins(20, 16, 20, 20);
    cl->setSpacing(12);
    auto* title_lbl = new QLabel(title, card);
    title_lbl->setStyleSheet(
        "color:#6B5B4E; font-size:9pt; font-weight:700; letter-spacing:1px; background:transparent;");
    cl->addWidget(title_lbl);
    return {card, cl};
}

} // namespace

// ────────────────────────────────────────────────────────────────────────────
// BuildSettingsPage
// ────────────────────────────────────────────────────────────────────────────
QWidget* MainWindow::BuildSettingsPage() {
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");

    auto* root_l = new QVBoxLayout(page);
    root_l->setContentsMargins(0, 0, 0, 0);
    root_l->setSpacing(0);

    // ── Header bar ─────────────────────────────────────────────────────────
    auto* hdr = new QWidget(page);
    hdr->setFixedHeight(64);
    hdr->setStyleSheet(
        "background:#0E0904; border-bottom:1px solid rgba(255,170,90,20);");
    auto* hdr_l = new QHBoxLayout(hdr);
    hdr_l->setContentsMargins(24, 0, 24, 0);
    hdr_l->setSpacing(14);

    auto* hdr_icon = new SettingsIcon(SettingsIcon::Type::Shield, 28, hdr);
    hdr_l->addWidget(hdr_icon);

    auto* hdr_texts = new QVBoxLayout();
    hdr_texts->setSpacing(0);
    auto* hdr_title = new QLabel(QString::fromUtf8("C\xc3\xa0i \xc4\x91\xe1\xba\xb7t"), hdr);
    hdr_title->setStyleSheet("color:#FFFFFF; font-size:14pt; font-weight:700; background:transparent;");
    auto* hdr_sub = new QLabel(QString::fromUtf8("C\xe1\xba\xa5u h\xc3\xacnh h\xe1\xbb\x87 th\xe1\xbb\x91ng v\xc3\xa0 b\xe1\xba\xa3o m\xe1\xba\xadt"), hdr);
    hdr_sub->setStyleSheet("color:#6B5B4E; font-size:8.5pt; background:transparent;");
    hdr_texts->addWidget(hdr_title);
    hdr_texts->addWidget(hdr_sub);
    hdr_l->addLayout(hdr_texts);
    hdr_l->addStretch();
    root_l->addWidget(hdr);

    // ── Body: sidebar + content ────────────────────────────────────────────
    auto* body = new QWidget(page);
    body->setStyleSheet("background:#120B06;");
    auto* body_l = new QHBoxLayout(body);
    body_l->setContentsMargins(0, 0, 0, 0);
    body_l->setSpacing(0);
    root_l->addWidget(body, 1);

    // ── Sidebar ────────────────────────────────────────────────────────────
    auto* sidebar = new QWidget(body);
    sidebar->setFixedWidth(220);
    sidebar->setStyleSheet(
        "background:rgba(14,9,4,240); border-right:1px solid rgba(255,170,90,20);");
    auto* sb_l = new QVBoxLayout(sidebar);
    sb_l->setContentsMargins(14, 20, 14, 20);
    sb_l->setSpacing(4);

    // Logo row in sidebar
    auto* logo_row = new QHBoxLayout();
    logo_row->setSpacing(10);
    auto* logo_box = new QWidget(sidebar);
    logo_box->setFixedSize(36, 36);
    logo_box->setStyleSheet(
        "background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #FF7A00,stop:1 #CC5500);"
        " border-radius:10px;");
    logo_row->addWidget(logo_box);
    auto* logo_texts = new QVBoxLayout();
    logo_texts->setSpacing(0);
    auto* logo_name = new QLabel("TeoAVSuite", sidebar);
    logo_name->setStyleSheet("color:#FF9B3D; font-size:9.5pt; font-weight:700; background:transparent;");
    auto* logo_sub2 = new QLabel("Settings", sidebar);
    logo_sub2->setStyleSheet("color:#6B5B4E; font-size:8pt; background:transparent;");
    logo_texts->addWidget(logo_name);
    logo_texts->addWidget(logo_sub2);
    logo_row->addLayout(logo_texts);
    sb_l->addLayout(logo_row);

    auto* sep = new QFrame(sidebar);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color:rgba(255,170,90,20); margin:8px 0;");
    sb_l->addWidget(sep);

    // Nav buttons
    struct NavItem { SettingsIcon::Type icon; const char* label; };
    const NavItem navItems[] = {
        { SettingsIcon::Type::Shield,       "Realtime"  },
        { SettingsIcon::Type::FolderSearch, "Scan"      },
        { SettingsIcon::Type::Cpu,          "Engine"    },
        { SettingsIcon::Type::Bot,          "AI Model"  },
        { SettingsIcon::Type::Lock,         "Security"  },
    };
    constexpr int kNavCount = 5;

    auto* stacked = new QStackedWidget();

    // nav_btns must outlive BuildSettingsPage: the per-button click lambdas are
    // invoked long after this function returns. Capturing a local QVector by
    // reference left them dangling — garbage size → the qlist.h assert / crash
    // when switching Settings tabs. Hold it in a shared_ptr captured by value.
    auto nav_btns = std::make_shared<QVector<QPushButton*>>();
    nav_btns->reserve(kNavCount);

    auto setNavActive = [nav_btns](int idx) {
        for (int i = 0; i < nav_btns->size(); ++i) {
            (*nav_btns)[i]->setStyleSheet(
                i == idx
                ? "QPushButton { background:rgba(255,122,0,38); border:1px solid rgba(255,122,0,64);"
                  " border-radius:10px; color:#FF7A00; font-size:10pt; font-weight:600;"
                  " text-align:left; padding:0 10px; }"
                : "QPushButton { background:transparent; border:1px solid transparent;"
                  " border-radius:10px; color:#C7B6A2; font-size:10pt; font-weight:400;"
                  " text-align:left; padding:0 10px; }"
                  "QPushButton:hover { background:rgba(255,122,0,14); }");
        }
    };

    for (int i = 0; i < kNavCount; ++i) {
        auto* btn_row = new QWidget(sidebar);
        btn_row->setFixedHeight(44);
        auto* btn_rl = new QHBoxLayout(btn_row);
        btn_rl->setContentsMargins(0, 0, 0, 0);
        btn_rl->setSpacing(8);

        auto* ic = new SettingsIcon(navItems[i].icon, 18, btn_row);
        ic->color_ = (i == 0) ? QColor(0xFF, 0x7A, 0x00) : QColor(0xC7, 0xB6, 0xA2);

        auto* btn = new QPushButton(navItems[i].label, btn_row);
        btn->setFixedHeight(44);
        btn->setCursor(Qt::PointingHandCursor);
        nav_btns->append(btn);

        btn_rl->addWidget(ic);
        btn_rl->addWidget(btn, 1);
        sb_l->addWidget(btn_row);

        // Capture i by value for connection
        connect(btn, &QPushButton::clicked, btn, [i, stacked, nav_btns, setNavActive]() mutable {
            stacked->setCurrentIndex(i);
            setNavActive(i);
            for (int j = 0; j < nav_btns->size(); ++j) {
                // Update icon colors by finding sibling SettingsIcon
                auto* brow = (*nav_btns)[j]->parentWidget();
                if (brow) {
                    for (auto* ch : brow->children()) {
                        if (auto* si = dynamic_cast<SettingsIcon*>(
                                dynamic_cast<QWidget*>(ch))) {
                            si->color_ = (j == i)
                                ? QColor(0xFF, 0x7A, 0x00)
                                : QColor(0xC7, 0xB6, 0xA2);
                            si->update();
                        }
                    }
                }
            }
        });
    }
    setNavActive(0);

    sb_l->addStretch();
    body_l->addWidget(sidebar);

    // ── Content scroll area ────────────────────────────────────────────────
    auto* scroll = new QScrollArea(body);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet(
        "QScrollArea { background:#120B06; border:none; }"
        "QScrollBar:vertical { background:#1A120C; width:6px; border-radius:3px; }"
        "QScrollBar::handle:vertical { background:rgba(255,122,0,80); border-radius:3px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }");
    scroll->setWidget(stacked);
    body_l->addWidget(scroll, 1);

    stacked->setStyleSheet("background:#120B06;");

    // ─────────────────────────────────────────────────────────────────────
    // PAGE 0 — Realtime Protection
    // ─────────────────────────────────────────────────────────────────────
    {
        auto* pg = new QWidget();
        auto* pl = new QVBoxLayout(pg);
        pl->setContentsMargins(28, 28, 28, 28);
        pl->setSpacing(16);

        auto [card, cl] = makeCard(
            QString::fromUtf8("TH\xc6\xaf M\xe1\xbb\xa4" "C THEO D\xc3\x95I (REALTIME PROTECTION)"), pg);

        watch_dir_list_ = new QListWidget(card);
        watch_dir_list_->setStyleSheet(kListStyle);
        watch_dir_list_->setMinimumHeight(180);
        for (const auto& dir : config_.watch_directories)
            watch_dir_list_->addItem(QString::fromUtf8(dir.c_str()));
        cl->addWidget(watch_dir_list_);

        auto* btn_row = new QHBoxLayout();
        btn_row->setSpacing(10);
        auto* add_dir_btn = new QPushButton(
            QString::fromUtf8("+ Th\xc3\xaam th\xc6\xb0 m\xe1\xbb\xa5" "c"), card);
        add_dir_btn->setStyleSheet(kSmallBtnStyle);
        add_dir_btn->setCursor(Qt::PointingHandCursor);
        auto* remove_dir_btn = new QPushButton(
            QString::fromUtf8("\xe2\x88\x92 X\xc3\xb3" "a"), card);
        remove_dir_btn->setStyleSheet(kDangerBtnStyle);
        remove_dir_btn->setCursor(Qt::PointingHandCursor);
        btn_row->addWidget(add_dir_btn);
        btn_row->addWidget(remove_dir_btn);
        btn_row->addStretch();
        cl->addLayout(btn_row);

        QObject::connect(add_dir_btn,    &QPushButton::clicked, this, &MainWindow::OnAddWatchDirClicked);
        QObject::connect(remove_dir_btn, &QPushButton::clicked, this, &MainWindow::OnRemoveWatchDirClicked);

        pl->addWidget(card);

        auto* save_btn0 = new QPushButton(
            QString::fromUtf8("L\xc6\xb0u c\xe1\xba\xa5u h\xc3\xacnh"), pg);
        save_btn0->setStyleSheet(kSaveBtnStyle);
        save_btn0->setFixedHeight(44);
        save_btn0->setCursor(Qt::PointingHandCursor);
        QObject::connect(save_btn0, &QPushButton::clicked, this, &MainWindow::OnSaveSettingsClicked);
        pl->addWidget(save_btn0, 0, Qt::AlignLeft);
        pl->addStretch();
        stacked->addWidget(pg);
    }

    // ─────────────────────────────────────────────────────────────────────
    // PAGE 1 — Scheduled Scan
    // ─────────────────────────────────────────────────────────────────────
    {
        auto* pg = new QWidget();
        auto* pl = new QVBoxLayout(pg);
        pl->setContentsMargins(28, 28, 28, 28);
        pl->setSpacing(16);

        auto [card, cl] = makeCard(
            QString::fromUtf8("QU\xc3\x89T THEO L\xe1\xbb\x8a" "CH (SCHEDULED SCAN)"), pg);

        schedule_enabled_check_ = new QCheckBox(
            QString::fromUtf8("B\xe1\xba\xadt qu\xc3\xa9t t\xe1\xbb\xb1 \xc4\x91\xe1\xbb\x99ng"), card);
        schedule_enabled_check_->setStyleSheet(kCheckStyle);
        schedule_enabled_check_->setChecked(config_.scheduled_scan.enabled);
        cl->addWidget(schedule_enabled_check_);

        // Interval row
        {
            auto* row = new QHBoxLayout();
            row->setSpacing(12);
            row->addWidget(makeFormLabel(QString::fromUtf8("Chu k\xe1\xbb\xb3:"), card));
            schedule_interval_combo_ = new QComboBox(card);
            schedule_interval_combo_->setStyleSheet(kComboStyle);
            schedule_interval_combo_->addItem(QString::fromUtf8("H\xc3\xa0ng ng\xc3\xa0y"), "daily");
            schedule_interval_combo_->addItem(QString::fromUtf8("H\xc3\xa0ng tu\xe1\xba\xa7n"), "weekly");
            schedule_interval_combo_->addItem(QString::fromUtf8("Khi kh\xe1\xbb\x9fi \xc4\x91\xe1\xbb\x99ng"), "on_boot");
            const auto& iv = config_.scheduled_scan.interval;
            if (iv == "weekly")  schedule_interval_combo_->setCurrentIndex(1);
            else if (iv == "on_boot") schedule_interval_combo_->setCurrentIndex(2);
            else schedule_interval_combo_->setCurrentIndex(0);
            row->addWidget(schedule_interval_combo_);
            row->addStretch();
            cl->addLayout(row);
        }

        // Time row
        {
            auto* row = new QHBoxLayout();
            row->setSpacing(12);
            row->addWidget(makeFormLabel(QString::fromUtf8("Gi\xe1\xbb\x9d (HH:MM):"), card));
            schedule_time_edit_ = new QLineEdit(card);
            schedule_time_edit_->setStyleSheet(kLineEditStyle);
            schedule_time_edit_->setPlaceholderText("02:00");
            schedule_time_edit_->setFixedWidth(100);
            schedule_time_edit_->setText(QString::fromUtf8(config_.scheduled_scan.time_hhmm.c_str()));
            row->addWidget(schedule_time_edit_);
            row->addStretch();
            cl->addLayout(row);
        }

        // Path row
        {
            auto* row = new QHBoxLayout();
            row->setSpacing(12);
            row->addWidget(makeFormLabel(QString::fromUtf8("Th\xc6\xb0 m\xe1\xbb\xa5" "c qu\xc3\xa9t:"), card));
            schedule_path_edit_ = new QLineEdit(card);
            schedule_path_edit_->setStyleSheet(kLineEditStyle);
            schedule_path_edit_->setPlaceholderText(
                QString::fromUtf8("\xc4\x90\xe1\xba\xb7t tr\xe1\xbb\x91ng = qu\xc3\xa9t watch directories"));
            schedule_path_edit_->setText(
                QString::fromUtf8(config_.scheduled_scan.target_path.c_str()));
            row->addWidget(schedule_path_edit_, 1);
            cl->addLayout(row);
        }

        pl->addWidget(card);

        auto* save_btn1 = new QPushButton(
            QString::fromUtf8("L\xc6\xb0u c\xe1\xba\xa5u h\xc3\xacnh"), pg);
        save_btn1->setStyleSheet(kSaveBtnStyle);
        save_btn1->setFixedHeight(44);
        save_btn1->setCursor(Qt::PointingHandCursor);
        QObject::connect(save_btn1, &QPushButton::clicked, this, &MainWindow::OnSaveSettingsClicked);
        pl->addWidget(save_btn1, 0, Qt::AlignLeft);
        pl->addStretch();
        stacked->addWidget(pg);
    }

    // ─────────────────────────────────────────────────────────────────────
    // PAGE 2 — Engine
    // ─────────────────────────────────────────────────────────────────────
    {
        auto* pg = new QWidget();
        auto* pl = new QVBoxLayout(pg);
        pl->setContentsMargins(28, 28, 28, 28);
        pl->setSpacing(16);

        auto [card, cl] = makeCard(
            QString::fromUtf8("HI\xe1\xbb\x86U SU\xe1\xba\xa4T ENGINE"), pg);

        {
            auto* row = new QHBoxLayout();
            row->setSpacing(12);
            row->addWidget(makeFormLabel(QString::fromUtf8("Debounce (ms):"), card));
            debounce_spin_ = new QSpinBox(card);
            debounce_spin_->setStyleSheet(kSpinStyle);
            debounce_spin_->setRange(50, 10000);
            debounce_spin_->setValue(config_.debounce_ms);
            debounce_spin_->setFixedWidth(120);
            row->addWidget(debounce_spin_);
            auto* hint = new QLabel(
                QString::fromUtf8("Th\xe1\xbb\x9di gian ch\xe1\xbb\x9d tr\xc6\xb0\xe1\xbb\x9b" "c khi ph\xe1\xba\xa3n h\xe1\xbb\x93i s\xe1\xbb\xb1 ki\xe1\xbb\x87n filesystem"),
                card);
            hint->setStyleSheet("color:#4B3B2E; font-size:8.5pt; background:transparent;");
            row->addWidget(hint, 1);
            cl->addLayout(row);
        }

        pl->addWidget(card);

        auto* save_btn2 = new QPushButton(
            QString::fromUtf8("L\xc6\xb0u c\xe1\xba\xa5u h\xc3\xacnh"), pg);
        save_btn2->setStyleSheet(kSaveBtnStyle);
        save_btn2->setFixedHeight(44);
        save_btn2->setCursor(Qt::PointingHandCursor);
        QObject::connect(save_btn2, &QPushButton::clicked, this, &MainWindow::OnSaveSettingsClicked);
        pl->addWidget(save_btn2, 0, Qt::AlignLeft);
        pl->addStretch();
        stacked->addWidget(pg);
    }

    // ─────────────────────────────────────────────────────────────────────
    // PAGE 3 — AI Model
    // ─────────────────────────────────────────────────────────────────────
    {
        auto* pg = new QWidget();
        auto* pl = new QVBoxLayout(pg);
        pl->setContentsMargins(28, 28, 28, 28);
        pl->setSpacing(16);

        auto [card, cl] = makeCard(
            QString::fromUtf8("TR\xe1\xbb\xa2 L\xc3\x9d AI (LOCAL LLM)"), pg);

        {
            auto* row = new QHBoxLayout();
            row->setSpacing(10);
            row->addWidget(makeFormLabel(QString::fromUtf8("Model GGUF:"), card));
            ai_model_path_edit_ = new QLineEdit(card);
            ai_model_path_edit_->setStyleSheet(kLineEditStyle);
            ai_model_path_edit_->setPlaceholderText(
                "D:\\models\\qwen2.5-3b-instruct-q4_k_m.gguf");
            ai_model_path_edit_->setText(
                QString::fromUtf8(config_.ai_model_path.c_str()));
            row->addWidget(ai_model_path_edit_, 1);
            auto* ai_browse_btn = new QPushButton(QString::fromUtf8("\xf0\x9f\x93\x82"), card);
            ai_browse_btn->setFixedSize(36, 36);
            ai_browse_btn->setStyleSheet(kSmallBtnStyle);
            ai_browse_btn->setToolTip(QString::fromUtf8("Ch\xe1\xbb\x8dn file .gguf"));
            ai_browse_btn->setCursor(Qt::PointingHandCursor);
            QObject::connect(ai_browse_btn, &QPushButton::clicked, this, [this] {
                const QString path = QFileDialog::getOpenFileName(
                    this, QString::fromUtf8("Ch\xe1\xbb\x8dn model GGUF"),
                    QString(), QString::fromUtf8("GGUF model (*.gguf);;T\xe1\xba\xa5t c\xe1\xba\xa3 (*.*)"));
                if (!path.isEmpty()) ai_model_path_edit_->setText(path);
            });
            row->addWidget(ai_browse_btn);
            cl->addLayout(row);
        }

        // Info note
        auto* note = new QLabel(
            QString::fromUtf8("H\xe1\xbb\x97 tr\xe1\xbb\xa3: Qwen2.5, Phi-3.5, Mistral (GGUF format). "
                               "Kh\xe1\xbb\x9fi \xc4\x91\xe1\xbb\x99ng l\xe1\xba\xa1i \xe1\xbb\xa9ng d\xe1\xbb\xa5ng sau khi \xc4\x91\xe1\xbb\x95i model."),
            card);
        note->setStyleSheet("color:#4B3B2E; font-size:8.5pt; background:transparent;");
        note->setWordWrap(true);
        cl->addWidget(note);

        pl->addWidget(card);

        auto* save_btn3 = new QPushButton(
            QString::fromUtf8("L\xc6\xb0u c\xe1\xba\xa5u h\xc3\xacnh"), pg);
        save_btn3->setStyleSheet(kSaveBtnStyle);
        save_btn3->setFixedHeight(44);
        save_btn3->setCursor(Qt::PointingHandCursor);
        QObject::connect(save_btn3, &QPushButton::clicked, this, &MainWindow::OnSaveSettingsClicked);
        pl->addWidget(save_btn3, 0, Qt::AlignLeft);
        pl->addStretch();
        stacked->addWidget(pg);
    }

    // ─────────────────────────────────────────────────────────────────────
    // PAGE 4 — Security
    // ─────────────────────────────────────────────────────────────────────
    {
        auto* pg = new QWidget();
        auto* pl = new QVBoxLayout(pg);
        pl->setContentsMargins(28, 28, 28, 28);
        pl->setSpacing(16);

        auto [card, cl] = makeCard("VIRUSTOTAL API", pg);

        {
            auto* row = new QHBoxLayout();
            row->setSpacing(10);
            row->addWidget(makeFormLabel("API Key:", card));
            vt_key_edit_ = new QLineEdit(card);
            vt_key_edit_->setStyleSheet(kLineEditStyle);
            vt_key_edit_->setPlaceholderText(
                QString::fromUtf8("D\xc3\xa1n API key VirusTotal v3 t\xe1\xba\xa1i \xc4\x91\xc3\xa2y..."));
            vt_key_edit_->setEchoMode(QLineEdit::Password);
            vt_key_edit_->setText(
                QString::fromUtf8(config_.virustotal_api_key.c_str()));
            row->addWidget(vt_key_edit_, 1);
            auto* vt_show_btn = new QPushButton(QString::fromUtf8("\xf0\x9f\x91\x81"), card);
            vt_show_btn->setFixedSize(36, 36);
            vt_show_btn->setStyleSheet(kSmallBtnStyle);
            vt_show_btn->setCheckable(true);
            vt_show_btn->setCursor(Qt::PointingHandCursor);
            QObject::connect(vt_show_btn, &QPushButton::toggled, this, [this](bool checked) {
                vt_key_edit_->setEchoMode(
                    checked ? QLineEdit::Normal : QLineEdit::Password);
            });
            row->addWidget(vt_show_btn);
            cl->addLayout(row);
        }

        auto* vt_note = new QLabel(
            QString::fromUtf8("L\xe1\xba\xa5y API key mi\xe1\xbb\x85n ph\xc3\xad t\xe1\xba\xa1i virustotal.com \xe2\x80\x94 "
                               "gi\xe1\xbb\x9bi h\xe1\xba\xa1n 500 requests/ng\xc3\xa0y."),
            card);
        vt_note->setStyleSheet("color:#4B3B2E; font-size:8.5pt; background:transparent;");
        vt_note->setWordWrap(true);
        cl->addWidget(vt_note);

        pl->addWidget(card);

        auto [mb_card, mb_cl] = makeCard("MALWAREBAZAAR THREAT INTEL", pg);
        {
            auto* row = new QHBoxLayout();
            row->setSpacing(10);
            row->addWidget(makeFormLabel("Auth-Key:", mb_card));
            mb_key_edit_ = new QLineEdit(mb_card);
            mb_key_edit_->setStyleSheet(kLineEditStyle);
            mb_key_edit_->setPlaceholderText(
                QString::fromUtf8("D\xc3\xa1n Auth-Key abuse.ch MalwareBazaar t\xe1\xba\xa1i \xc4\x91\xc3\xa2y..."));
            mb_key_edit_->setEchoMode(QLineEdit::Password);
            mb_key_edit_->setText(
                QString::fromUtf8(config_.malwarebazaar_api_key.c_str()));
            row->addWidget(mb_key_edit_, 1);
            auto* mb_show_btn = new QPushButton(QString::fromUtf8("\xf0\x9f\x91\x81"), mb_card);
            mb_show_btn->setFixedSize(36, 36);
            mb_show_btn->setStyleSheet(kSmallBtnStyle);
            mb_show_btn->setCheckable(true);
            mb_show_btn->setCursor(Qt::PointingHandCursor);
            QObject::connect(mb_show_btn, &QPushButton::toggled, this, [this](bool checked) {
                mb_key_edit_->setEchoMode(
                    checked ? QLineEdit::Normal : QLineEdit::Password);
            });
            row->addWidget(mb_show_btn);
            mb_cl->addLayout(row);
        }
        auto* mb_note = new QLabel(
            QString::fromUtf8("D\xc3\xb9ng cho trang Threat Intel (n\xe1\xba\xa1p h\xe1\xba\xa5h m\xe1\xbb\x9bi t\xe1\xbb\xab abuse.ch MalwareBazaar v\xc3\xa0o blacklist). "
                               "L\xe1\xba\xa5y key mi\xe1\xbb\x85n ph\xc3\xad t\xe1\xba\xa1i bazaar.abuse.ch (Account -> API Key)."),
            mb_card);
        mb_note->setStyleSheet("color:#4B3B2E; font-size:8.5pt; background:transparent;");
        mb_note->setWordWrap(true);
        mb_cl->addWidget(mb_note);
        pl->addWidget(mb_card);

        auto* save_btn4 = new QPushButton(
            QString::fromUtf8("L\xc6\xb0u c\xe1\xba\xa5u h\xc3\xacnh"), pg);
        save_btn4->setStyleSheet(kSaveBtnStyle);
        save_btn4->setFixedHeight(44);
        save_btn4->setCursor(Qt::PointingHandCursor);
        QObject::connect(save_btn4, &QPushButton::clicked, this, &MainWindow::OnSaveSettingsClicked);
        pl->addWidget(save_btn4, 0, Qt::AlignLeft);
        pl->addStretch();
        stacked->addWidget(pg);
    }

    stacked->setCurrentIndex(0);
    return page;
}

} // namespace avdashboard
