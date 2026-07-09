#include <filesystem>

#include <QApplication>
#include <QMessageBox>
#include <QTimer>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "avcore/config.hpp"
#include "avlogging/logger.hpp"
#include "main_window.hpp"

namespace {

std::filesystem::path ExecutableDirectory() {
    char buffer[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    return std::filesystem::path(buffer).parent_path();
}

std::string ResolveNextToExe(const std::filesystem::path& exe_dir, const std::string& configured_path) {
    const std::filesystem::path path(configured_path);
    return path.is_absolute() ? configured_path : (exe_dir / path).string();
}

} // namespace

namespace {

// ── TeoAvSuite Amber Dark Theme ───────────────────────────────────────────────
// Deep brown-black + amber/orange accents — matches Figma Antivirus Dashboard.
constexpr const char* kStyleSheet = R"(

/* ── BASE ── */
QMainWindow, QWidget {
    background-color: #120B06;
    color: #C7B6A2;
    font-family: "Inter", "Segoe UI", sans-serif;
    font-size: 10pt;
}

/* ── SIDEBAR ── */
QWidget#Sidebar {
    background: #0E0804;
    border-right: 1px solid rgba(255,170,90,0.12);
}

QPushButton#NavButton {
    background: transparent;
    color: rgba(199,182,162,0.45);
    text-align: center;
    border: none;
    border-radius: 0px;
    border-right: 3px solid transparent;
    padding: 12px 4px;
    font-size: 18pt;
}
QPushButton#NavButton:hover {
    background: rgba(255,122,0,0.12);
    color: #FF9B3D;
}
QPushButton#NavButton:checked {
    background: rgba(255,122,0,0.16);
    color: #FF7A00;
    border-right: 3px solid #FF7A00;
}

/* ── BENTO CARDS ── */
QFrame#BentoHeroCard {
    background: qlineargradient(x1:0.1,y1:0,x2:0.9,y2:1,
        stop:0 #241408, stop:0.3 #2C1A0A, stop:0.65 #1E1108, stop:1 #140C04);
    border-top:    1px solid rgba(255,255,255,0.08);
    border-left:   1px solid rgba(255,255,255,0.05);
    border-right:  1px solid rgba(0,0,0,0.45);
    border-bottom: 4px solid rgba(0,0,0,0.60);
    border-radius: 14px;
}

QFrame#BentoStatsCard {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 rgba(36,23,14,0.98), stop:0.5 rgba(26,18,12,0.98), stop:1 rgba(30,18,8,0.98));
    border-top:    2px solid rgba(255,122,0,0.40);
    border-left:   1px solid rgba(255,122,0,0.18);
    border-right:  1px solid rgba(0,0,0,0.40);
    border-bottom: 2px solid rgba(0,0,0,0.60);
    border-radius: 14px;
}

QFrame#BentoActionsCard {
    background: qlineargradient(x1:0,y1:0,x2:0.8,y2:1,
        stop:0 #CC6200, stop:0.3 #B05500, stop:0.65 #9A4800, stop:1 #7A3800);
    border-top:    1px solid rgba(255,185,100,0.35);
    border-left:   1px solid rgba(255,155,61,0.22);
    border-right:  1px solid rgba(0,0,0,0.45);
    border-bottom: 5px solid rgba(40,15,0,0.80);
    border-radius: 14px;
}

QFrame#BentoChartCard {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #150A04, stop:0.4 #1A0E06, stop:0.8 #120904, stop:1 #0E0703);
    border-top:    1px solid rgba(255,122,0,0.18);
    border-left:   1px solid rgba(255,122,0,0.10);
    border-right:  1px solid rgba(0,0,0,0.35);
    border-bottom: 3px solid rgba(0,0,0,0.55);
    border-radius: 14px;
}

/* ── STAT CARDS ── */
QFrame#StatCard {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(44,29,18,0.75), stop:0.4 rgba(32,20,10,0.70), stop:1 rgba(20,12,4,0.65));
    border-top:    1px solid rgba(255,122,0,0.22);
    border-left:   1px solid rgba(255,122,0,0.12);
    border-right:  1px solid rgba(0,0,0,0.40);
    border-bottom: 3px solid rgba(0,0,0,0.55);
    border-radius: 10px;
}

/* ── STATUS CIRCLE ── */
QFrame#StatusCircle {
    background: qradialgradient(cx:0.38,cy:0.32,radius:0.9,
        stop:0 rgba(74,222,128,0.22), stop:0.6 rgba(74,222,128,0.08), stop:1 rgba(0,0,0,0));
    border: 5px solid rgba(74,222,128,0.80);
    border-radius: 84px;
}

/* ── QUICK TILES (CyberTile paints itself, these are fallbacks) ── */
QPushButton#QuickTile {
    background: transparent;
    border: none;
    border-radius: 11px;
    font-weight: 700;
    font-size: 9.5pt;
    padding: 0px;
}

/* ── GENERAL BUTTONS ── */
QPushButton {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #FF8C20, stop:0.44 #F07200, stop:0.5 #E06800, stop:1 #C04800);
    color: #ffffff;
    border-top:    1px solid rgba(255,200,100,0.22);
    border-left:   1px solid rgba(255,180,80,0.12);
    border-right:  1px solid rgba(0,0,0,0.30);
    border-bottom: 3px solid rgba(60,20,0,0.85);
    border-radius: 7px;
    padding: 7px 16px;
    font-weight: 700;
    letter-spacing: 0.3px;
}
QPushButton:hover {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #FFA040, stop:0.44 #FF8020, stop:0.5 #F07000, stop:1 #D05800);
}
QPushButton:pressed {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #C04800, stop:1 #A03800);
    border-top:    2px solid rgba(0,0,0,0.35);
    border-bottom: 1px solid rgba(60,20,0,0.40);
    padding-top: 9px;
    padding-bottom: 5px;
}
QPushButton:disabled {
    background: rgba(255,255,255,0.06);
    color: rgba(255,255,255,0.18);
    border-color: transparent;
}

QPushButton#DangerButton {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #FF6070, stop:0.44 #E83B50, stop:0.5 #D03050, stop:1 #A01838);
    border-top:    1px solid rgba(255,120,140,0.35);
    border-left:   1px solid rgba(255,100,120,0.20);
    border-right:  1px solid rgba(0,0,0,0.30);
    border-bottom: 3px solid rgba(80,0,20,0.80);
}
QPushButton#DangerButton:hover {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #FF7080, stop:0.44 #F04A60, stop:0.5 #E03858, stop:1 #B02040);
}

QPushButton#SuccessButton {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #45E888, stop:0.44 #2ECC71, stop:0.5 #28B864, stop:1 #1A8848);
    color: #05160D;
    border-top:    1px solid rgba(120,255,180,0.32);
    border-bottom: 3px solid rgba(0,50,20,0.80);
}
QPushButton#SuccessButton:hover {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #55F099, stop:0.44 #38D878, stop:0.5 #30C86A, stop:1 #229855);
}

QPushButton#SelectButton {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #4DB8FF, stop:0.44 #2A9FE8, stop:0.5 #1E8FD8, stop:1 #1470B0);
    color: #ffffff;
    border-top:    1px solid rgba(100,200,255,0.35);
    border-left:   1px solid rgba(80,180,255,0.22);
    border-right:  1px solid rgba(0,0,0,0.30);
    border-bottom: 3px solid rgba(10,40,80,0.80);
}
QPushButton#SelectButton:hover {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #5DC7FF, stop:0.44 #3AAEE8, stop:0.5 #2D9FD8, stop:1 #227FBF);
}

/* ── LABELS ── */
QLabel#StatusLabel {
    color: rgba(199,182,162,0.55);
    font-style: italic;
    padding: 4px 2px;
}

/* ── GROUPBOX ── */
QGroupBox {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(30,18,8,0.60), stop:1 rgba(18,10,4,0.55));
    border-top:    1px solid rgba(255,122,0,0.18);
    border-left:   1px solid rgba(255,122,0,0.10);
    border-right:  1px solid rgba(0,0,0,0.35);
    border-bottom: 2px solid rgba(0,0,0,0.45);
    border-radius: 10px;
    margin-top: 14px;
    font-weight: 700;
    color: rgba(199,182,162,0.75);
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 5px;
    color: rgba(255,155,61,0.85);
    background: transparent;
}

/* ── LISTS ── */
QListWidget {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(20,12,4,0.90), stop:1 rgba(12,7,2,0.85));
    border: 1px solid rgba(255,122,0,0.14);
    border-radius: 8px;
    color: #C7B6A2;
    alternate-background-color: rgba(36,23,14,0.40);
    selection-background-color: rgba(255,122,0,0.25);
    selection-color: #ffffff;
}

/* ── TABS ── */
QTabWidget::pane {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(20,12,4,0.80), stop:1 rgba(12,7,2,0.75));
    border: 1px solid rgba(255,122,0,0.14);
    border-radius: 0 8px 8px 8px;
}
QTabBar::tab {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(32,20,8,0.80), stop:1 rgba(18,10,4,0.75));
    color: rgba(199,182,162,0.55);
    padding: 8px 22px;
    border-top:    1px solid rgba(255,122,0,0.16);
    border-left:   1px solid rgba(255,122,0,0.10);
    border-right:  1px solid rgba(0,0,0,0.20);
    border-bottom: none;
    border-top-left-radius:  6px;
    border-top-right-radius: 6px;
    font-weight: 600;
}
QTabBar::tab:selected {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(44,28,8,0.95), stop:1 rgba(26,16,4,0.95));
    color: #ffffff;
    border-top:    2px solid #FF7A00;
    border-left:   1px solid rgba(255,122,0,0.28);
    border-bottom: 1px solid rgba(26,16,4,0.95);
}
QTabBar::tab:hover:!selected {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(38,24,8,0.80), stop:1 rgba(24,14,4,0.80));
    color: #E8D4B8;
}

/* ── CHECKBOXES ── */
QCheckBox { color: rgba(199,182,162,0.85); spacing: 8px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 2px solid rgba(255,122,0,0.35);
    border-radius: 4px;
    background: rgba(20,10,4,0.70);
}
QCheckBox::indicator:checked {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #FF9B3D, stop:1 #E06800);
    border-color: #FF7A00;
}

/* ── INPUTS ── */
QSpinBox, QLineEdit, QComboBox {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(28,18,8,0.88), stop:1 rgba(16,10,4,0.85));
    border: 1px solid rgba(255,122,0,0.18);
    border-radius: 7px;
    padding: 6px 10px;
    color: #C7B6A2;
    selection-background-color: rgba(255,122,0,0.28);
}
QSpinBox:focus, QLineEdit:focus, QComboBox:focus {
    border: 1px solid rgba(255,122,0,0.65);
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(40,24,8,0.95), stop:1 rgba(24,14,4,0.90));
}
QComboBox::drop-down { border: none; width: 20px; }
QComboBox QAbstractItemView {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #1A0E06, stop:1 #120904);
    border: 1px solid rgba(255,122,0,0.22);
    color: #C7B6A2;
    selection-background-color: rgba(255,122,0,0.22);
    selection-color: #ffffff;
}

/* ── TABLES ── */
QTableWidget {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(20,12,4,0.92), stop:1 rgba(12,7,2,0.88));
    border: 1px solid rgba(255,122,0,0.14);
    border-radius: 8px;
    gridline-color: rgba(255,122,0,0.05);
    color: #C7B6A2;
    alternate-background-color: rgba(36,23,14,0.30);
    selection-background-color: rgba(255,122,0,0.20);
    selection-color: #ffffff;
}
QHeaderView::section {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(36,23,14,0.98), stop:1 rgba(22,14,6,0.98));
    color: rgba(255,155,61,0.90);
    padding: 7px 8px;
    border: none;
    border-bottom: 2px solid rgba(255,122,0,0.28);
    border-right:  1px solid rgba(255,122,0,0.06);
    font-weight: 700;
    font-size: 9pt;
    letter-spacing: 0.6px;
}

/* ── SCROLLBARS ── */
QScrollBar:vertical {
    background: rgba(14,8,4,0.50);
    width: 6px; border-radius: 3px; margin: 3px 1px;
}
QScrollBar::handle:vertical {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 rgba(255,122,0,0.50), stop:1 rgba(255,122,0,0.30));
    border-radius: 3px; min-height: 22px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background: rgba(14,8,4,0.50);
    height: 6px; border-radius: 3px; margin: 1px 3px;
}
QScrollBar::handle:horizontal {
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 rgba(255,122,0,0.50), stop:1 rgba(255,122,0,0.30));
    border-radius: 3px; min-width: 22px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── PROGRESS BAR ── */
QProgressBar {
    background: rgba(20,10,4,0.60);
    border: 1px solid rgba(255,122,0,0.14);
    border-radius: 4px;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #E06800, stop:0.5 #FF7A00, stop:1 #FF9B3D);
    border-radius: 4px;
}

)";

} // namespace

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    app.setStyleSheet(kStyleSheet);

    const auto exe_dir = ExecutableDirectory();
    avcore::Config config = avcore::Config::LoadFromFile((exe_dir / "avsuite.json").string());
    config.database_path = ResolveNextToExe(exe_dir, config.database_path);
    config.log_path = ResolveNextToExe(exe_dir, config.log_path);
    config.yara_rules_directory = ResolveNextToExe(exe_dir, config.yara_rules_directory);
    config.quarantine_directory = ResolveNextToExe(exe_dir, config.quarantine_directory);

    avlogging::Logger::Init(config.log_path);

    FILE* dbg = nullptr;
    fopen_s(&dbg, "C:\\Users\\teohumble\\AppData\\Local\\Temp\\avdbg.txt", "w");
    if (dbg) { fprintf(dbg, "Before constructor\n"); fflush(dbg); }

    avdashboard::MainWindow window(std::move(config));

    if (dbg) { fprintf(dbg, "After constructor\n"); fflush(dbg); }

    window.show();
    if (dbg) { fprintf(dbg, "After show()\n"); fflush(dbg); }

    HWND hwnd = reinterpret_cast<HWND>(window.winId());
    if (dbg) { fprintf(dbg, "winId=0x%llx vis=%d\n", (unsigned long long)hwnd, hwnd ? ::IsWindowVisible(hwnd) : -1); fflush(dbg); }

    // Position/size is chosen in MainWindow's ctor (screen-aware + centered);
    // don't override it here.
    window.raise();
    window.activateWindow();
    if (hwnd) { ::ShowWindow(hwnd, SW_SHOW); ::SetForegroundWindow(hwnd); }

    if (dbg) { fprintf(dbg, "Before exec()\n"); fclose(dbg); }

    return app.exec();
}
