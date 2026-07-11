// main_window_wificsi.cpp — WiFi CSI Sensing page.
//
// Reads WiFi Channel State Info (per-subcarrier signal amplitude) from a
// CSI-capable card over a serial port (the common wire format for small
// CSI boards, e.g. ESP32-CSI-style tools: one text line per frame, comma-
// separated subcarrier amplitudes) and treats a jump in signal variance as
// a "motion detected" physical-presence event — a cheap through-the-air
// motion/intrusion sensor to complement LAN Monitor's on-the-wire view.
//
// HONESTY NOTE: the exact framing/units of the "SGP Card Mini" board were
// not confirmed with the user (no response when asked), so this reads
// plain comma/space-separated floats per line, which is the most common
// self-reported CSI-over-UART format -- it may need adjustment once real
// hardware confirms the wire format. Ships with a clearly-labeled
// Simulated mode (sine + noise + periodic synthetic "motion" bursts) so
// the page is demoable and testable without hardware. ASCII labels (MSVC
// builds without /utf-8).

#include "main_window.hpp"
#include "theme.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QComboBox>
#include <QConicalGradient>
#include <QDateTime>
#include <QFont>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#define NOMINMAX
#include <windows.h>
#include <wlanapi.h>
#pragma comment(lib, "wlanapi.lib")

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace avdashboard {
namespace {

constexpr int kSubcarriers = 64;

struct CsiFrame {
    std::vector<float> amplitudes; // one entry per subcarrier, 0..~1 normalized-ish
    qint64 t_ms = 0;
    QString raw_line; // empty for simulated frames
};

// ─── Thread-safe frame queue shared between the reader thread and the UI ──
class FrameQueue {
public:
    void Push(CsiFrame f) {
        std::lock_guard<std::mutex> lk(m_);
        q_.push_back(std::move(f));
        if (q_.size() > 200) q_.pop_front(); // bound memory if UI falls behind
    }
    bool Pop(CsiFrame& out) {
        std::lock_guard<std::mutex> lk(m_);
        if (q_.empty()) return false;
        out = std::move(q_.front());
        q_.pop_front();
        return true;
    }
private:
    std::mutex m_;
    std::deque<CsiFrame> q_;
};

// ─── Simulated source: sine + noise per subcarrier, periodic motion burst ─
class SimSource {
public:
    explicit SimSource(std::shared_ptr<FrameQueue> q) : q_(std::move(q)) {}
    void Start() {
        stop_.store(false);
        th_ = std::thread([this] { Run(); });
    }
    void Stop() {
        stop_.store(true);
        if (th_.joinable()) th_.join();
    }
private:
    void Run() {
        std::mt19937 rng(std::random_device{}());
        std::normal_distribution<float> noise(0.0f, 0.03f);
        int tick = 0;
        while (!stop_.load()) {
            CsiFrame f;
            f.amplitudes.resize(kSubcarriers);
            const bool burst = (tick % 160) > 140; // ~1.5s burst every ~8s at 20fps
            for (int i = 0; i < kSubcarriers; ++i) {
                float base = 0.4f + 0.15f * std::sin(0.15f * i + tick * 0.05f);
                float n = noise(rng) * (burst ? 4.0f : 1.0f);
                f.amplitudes[i] = std::clamp(base + n, 0.0f, 1.0f);
            }
            f.t_ms = QDateTime::currentMSecsSinceEpoch();
            q_->Push(std::move(f));
            ++tick;
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // ~20fps
        }
    }
    std::shared_ptr<FrameQueue> q_;
    std::thread th_;
    std::atomic<bool> stop_{false};
};

// ─── Serial source: one CSV-of-floats line per frame over a COM port ──────
class SerialSource {
public:
    SerialSource(std::shared_ptr<FrameQueue> q, std::string port, int baud)
        : q_(std::move(q)), port_(std::move(port)), baud_(baud) {}

    bool Start(std::string* error_out) {
        const std::string path = "\\\\.\\" + port_;
        handle_ = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) {
            if (error_out) *error_out = "Khong mo duoc " + port_ + " (dang duoc dung boi ung dung khac?).";
            return false;
        }
        DCB dcb{}; dcb.DCBlength = sizeof(dcb);
        if (!GetCommState(handle_, &dcb)) { Close(); if (error_out) *error_out = "GetCommState that bai."; return false; }
        dcb.BaudRate = static_cast<DWORD>(baud_);
        dcb.ByteSize = 8; dcb.Parity = NOPARITY; dcb.StopBits = ONESTOPBIT;
        if (!SetCommState(handle_, &dcb)) { Close(); if (error_out) *error_out = "SetCommState that bai."; return false; }

        COMMTIMEOUTS to{};
        to.ReadIntervalTimeout = 50;
        to.ReadTotalTimeoutConstant = 200;
        to.ReadTotalTimeoutMultiplier = 1;
        SetCommTimeouts(handle_, &to);

        stop_.store(false);
        th_ = std::thread([this] { Run(); });
        return true;
    }
    void Stop() {
        stop_.store(true);
        if (th_.joinable()) th_.join();
        Close();
    }
private:
    void Close() {
        if (handle_ != INVALID_HANDLE_VALUE) { CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE; }
    }
    void Run() {
        std::string line_buf;
        char chunk[512];
        while (!stop_.load()) {
            DWORD read = 0;
            if (!ReadFile(handle_, chunk, sizeof(chunk), &read, nullptr) || read == 0) continue;
            for (DWORD i = 0; i < read; ++i) {
                const char c = chunk[i];
                if (c == '\n' || c == '\r') {
                    if (!line_buf.empty()) { ParseLine(line_buf); line_buf.clear(); }
                } else {
                    line_buf += c;
                    if (line_buf.size() > 8192) line_buf.clear(); // guard against garbage/no-delimiter noise
                }
            }
        }
    }
    void ParseLine(const std::string& line) {
        CsiFrame f;
        f.raw_line = QString::fromStdString(line).left(200);
        std::string cur;
        auto flush = [&] {
            if (!cur.empty()) {
                try { f.amplitudes.push_back(std::stof(cur)); } catch (...) {}
                cur.clear();
            }
        };
        for (char c : line) {
            if (c == ',' || c == ' ' || c == '\t' || c == ';') flush();
            else cur += c;
        }
        flush();
        if (f.amplitudes.empty()) return; // not a numeric CSI line (log/debug text from the board) -- skip
        f.t_ms = QDateTime::currentMSecsSinceEpoch();
        q_->Push(std::move(f));
    }

    std::shared_ptr<FrameQueue> q_;
    std::string port_;
    int baud_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::thread th_;
    std::atomic<bool> stop_{false};
};

// ─── Real radio scan: nearby WiFi access points via the Native WiFi API ──
// This is an actual scan of the radio spectrum around this machine (the
// same data `netsh wlan show networks` reads), not simulated -- BSSID,
// SSID, and real received signal strength (RSSI, dBm) per AP.
struct WifiDevice {
    std::string ssid;
    std::string bssid;
    int rssi_dbm = -100;
};

// Stable per-device angle so a given AP doesn't jump around between scans
// -- NOT a real compass bearing (Wi-Fi scanning gives no direction info,
// only presence + signal strength). Radius is what's physically meaningful
// here: stronger RSSI = plotted closer to center.
double StableAngleForBssid(const std::string& bssid) {
    unsigned int h = 2166136261u;
    for (char c : bssid) { h ^= static_cast<unsigned char>(c); h *= 16777619u; }
    return static_cast<double>(h % 360);
}

std::vector<WifiDevice> ScanWifiOnce() {
    std::vector<WifiDevice> out;
    HANDLE hClient = nullptr;
    DWORD negotiated = 0;
    if (WlanOpenHandle(2, nullptr, &negotiated, &hClient) != ERROR_SUCCESS || !hClient) return out;

    PWLAN_INTERFACE_INFO_LIST ifaceList = nullptr;
    if (WlanEnumInterfaces(hClient, nullptr, &ifaceList) == ERROR_SUCCESS && ifaceList) {
        for (DWORD i = 0; i < ifaceList->dwNumberOfItems; ++i) {
            const GUID ifaceGuid = ifaceList->InterfaceInfo[i].InterfaceGuid;
            WlanScan(hClient, &ifaceGuid, nullptr, nullptr, nullptr); // trigger an active scan; best-effort

            PWLAN_BSS_LIST bssList = nullptr;
            if (WlanGetNetworkBssList(hClient, &ifaceGuid, nullptr, dot11_BSS_type_any,
                                       FALSE, nullptr, &bssList) == ERROR_SUCCESS && bssList) {
                for (DWORD j = 0; j < bssList->dwNumberOfItems; ++j) {
                    const WLAN_BSS_ENTRY& e = bssList->wlanBssEntries[j];
                    WifiDevice d;
                    const ULONG len = std::min<ULONG>(e.dot11Ssid.uSSIDLength, 32);
                    d.ssid.assign(reinterpret_cast<const char*>(e.dot11Ssid.ucSSID), len);
                    if (d.ssid.empty()) d.ssid = "(hidden)";
                    char mac[18];
                    std::snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                                  e.dot11Bssid[0], e.dot11Bssid[1], e.dot11Bssid[2],
                                  e.dot11Bssid[3], e.dot11Bssid[4], e.dot11Bssid[5]);
                    d.bssid = mac;
                    d.rssi_dbm = e.lRssi;
                    out.push_back(std::move(d));
                }
                WlanFreeMemory(bssList);
            }
        }
        WlanFreeMemory(ifaceList);
    }
    WlanCloseHandle(hClient, nullptr);
    return out;
}

// Periodic background scanner -- WlanScan+WlanGetNetworkBssList takes real
// wall-clock time (the driver has to actually listen on-air), so this runs
// every few seconds on its own thread rather than per-UI-frame.
class WifiRadarSource {
public:
    explicit WifiRadarSource(std::function<void(std::vector<WifiDevice>)> on_result)
        : on_result_(std::move(on_result)) {}
    void Start() {
        stop_.store(false);
        th_ = std::thread([this] { Run(); });
    }
    void Stop() {
        stop_.store(true);
        if (th_.joinable()) th_.join();
    }
private:
    void Run() {
        while (!stop_.load()) {
            auto devices = ScanWifiOnce();
            if (stop_.load()) break;
            on_result_(std::move(devices));
            for (int i = 0; i < 40 && !stop_.load(); ++i) // ~4s between scans, checked every 100ms so Stop() is snappy
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    std::function<void(std::vector<WifiDevice>)> on_result_;
    std::thread th_;
    std::atomic<bool> stop_{false};
};

// ─── Small custom-painted bar view of the latest frame's amplitudes ───────
class CsiWaveWidget : public QWidget {
public:
    explicit CsiWaveWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setMinimumHeight(140);
    }
    void SetFrame(const std::vector<float>& amps) { amps_ = amps; update(); }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.fillRect(rect(), QColor(0x1C, 0x10, 0x08));
        if (amps_.empty()) {
            p.setPen(QColor(0x8B, 0x8B, 0x8B));
            p.drawText(rect(), Qt::AlignCenter, QString::fromUtf8("No data"));
            return;
        }
        const int n = static_cast<int>(amps_.size());
        const double w = static_cast<double>(width()) / n;
        for (int i = 0; i < n; ++i) {
            const double h = std::clamp(static_cast<double>(amps_[i]), 0.0, 1.0) * (height() - 6);
            QColor c(0x4A, 0xDE, 0x80);
            if (amps_[i] > 0.7f) c = QColor(0xFF, 0x7A, 0x00);
            if (amps_[i] > 0.9f) c = QColor(0xFF, 0x3B, 0x50);
            p.fillRect(QRectF(i * w + 1, height() - h, std::max(1.0, w - 1), h), c);
        }
    }
private:
    std::vector<float> amps_;
};

// ─── Radar-sweep view: each subcarrier plotted in polar coordinates ───────
// (angle = subcarrier index around 360deg, radius = amplitude) with a
// rotating sweep line/trail for the classic radar look, and a flashing
// ring when a motion event fires. This is a real-data polar plot, not a
// simulated/random display -- there's no angle-of-arrival hardware here,
// so "angle" is just each subcarrier's slot around the circle, not an
// actual physical bearing to whatever caused the motion.
class RadarWidget : public QWidget {
public:
    explicit RadarWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setMinimumSize(260, 260);
    }
    void SetFrame(const std::vector<float>& amps) { amps_ = amps; devices_.clear(); update(); }
    void SetSweepAngle(double deg) { sweep_deg_ = deg; update(); }
    void Flash() { flash_started_ = QDateTime::currentMSecsSinceEpoch(); }

    // Real WiFi devices: angle is stable-per-BSSID (not a compass bearing --
    // WiFi scanning carries no direction info), radius maps signal strength
    // (stronger RSSI = closer to center, weaker = toward the edge).
    void SetDevices(const std::vector<WifiDevice>& devices) {
        devices_ = devices;
        amps_.clear();
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const double side = std::min(width(), height());
        const QPointF center(width() / 2.0, height() / 2.0);
        const double R = side / 2.0 - 8.0;

        p.fillRect(rect(), QColor(0x10, 0x08, 0x04));

        // Range rings + crosshair.
        p.setPen(QPen(QColor(0x2A, 0x1F, 0x14), 1));
        for (int ring = 1; ring <= 4; ++ring) {
            const double r = R * ring / 4.0;
            p.drawEllipse(center, r, r);
        }
        p.drawLine(QPointF(center.x() - R, center.y()), QPointF(center.x() + R, center.y()));
        p.drawLine(QPointF(center.x(), center.y() - R), QPointF(center.x(), center.y() + R));

        // Sweep trail (fading wedge behind the current angle) + sweep line.
        QConicalGradient grad(center, sweep_deg_);
        grad.setColorAt(0.000, QColor(0xFF, 0x7A, 0x00, 170));
        grad.setColorAt(0.070, QColor(0xFF, 0x7A, 0x00, 50));
        grad.setColorAt(0.140, QColor(0xFF, 0x7A, 0x00, 0));
        grad.setColorAt(1.000, QColor(0xFF, 0x7A, 0x00, 0));
        p.setPen(Qt::NoPen);
        p.setBrush(grad);
        p.drawEllipse(center, R, R);

        const double sweep_rad = sweep_deg_ * M_PI / 180.0;
        p.setPen(QPen(QColor(0xFF, 0x7A, 0x00), 1.6));
        p.drawLine(center, QPointF(center.x() + R * std::cos(sweep_rad),
                                    center.y() - R * std::sin(sweep_rad)));

        // Blips: one per subcarrier, angle = its slot around the circle,
        // radius = its current amplitude.
        if (!amps_.empty()) {
            const int n = static_cast<int>(amps_.size());
            for (int i = 0; i < n; ++i) {
                const double a = std::clamp(static_cast<double>(amps_[i]), 0.0, 1.0);
                const double deg = 360.0 * i / n;
                const double rad = deg * M_PI / 180.0;
                const double r = a * R;
                const QPointF pt(center.x() + r * std::cos(rad), center.y() - r * std::sin(rad));
                QColor c(0x4A, 0xDE, 0x80);
                if (a > 0.7) c = QColor(0xFF, 0x7A, 0x00);
                if (a > 0.9) c = QColor(0xFF, 0x3B, 0x50);
                p.setPen(Qt::NoPen);
                p.setBrush(c);
                p.drawEllipse(pt, 2.2, 2.2);
            }
        }

        // Real WiFi devices: bigger labeled blips, radius from real RSSI.
        if (!devices_.empty()) {
            p.setFont(QFont(p.font().family(), 7));
            for (const auto& d : devices_) {
                const double deg = StableAngleForBssid(d.bssid);
                const double rad = deg * M_PI / 180.0;
                // -30dBm (very strong/close) -> r~0 ; -90dBm (weak/far) -> r~R.
                const double norm = std::clamp((-d.rssi_dbm - 30.0) / 60.0, 0.0, 1.0);
                const double r = norm * R;
                const QPointF pt(center.x() + r * std::cos(rad), center.y() - r * std::sin(rad));
                QColor c(0x4A, 0xDE, 0x80);
                if (d.rssi_dbm < -75) c = QColor(0xFF, 0x7A, 0x00);
                if (d.rssi_dbm < -85) c = QColor(0xFF, 0x3B, 0x50);
                p.setPen(Qt::NoPen);
                p.setBrush(c);
                p.drawEllipse(pt, 4.0, 4.0);
                p.setPen(QColor(0xE8, 0xE8, 0xE8));
                p.drawText(pt + QPointF(6, 3), QString::fromStdString(d.ssid));
            }
        }

        // Motion flash: expanding/fading red ring for ~900ms after Flash().
        if (flash_started_ > 0) {
            const qint64 elapsed = QDateTime::currentMSecsSinceEpoch() - flash_started_;
            if (elapsed < 900) {
                const double t = elapsed / 900.0;
                const double fr = R * (0.3 + 0.7 * t);
                QColor ring(0xFF, 0x3B, 0x50, static_cast<int>(220 * (1.0 - t)));
                p.setPen(QPen(ring, 2.5));
                p.setBrush(Qt::NoBrush);
                p.drawEllipse(center, fr, fr);
            } else {
                flash_started_ = 0;
            }
        }

        p.setPen(QColor(0x8B, 0x8B, 0x8B));
        p.setFont(QFont(p.font().family(), 7));
        p.drawText(rect().adjusted(6, 4, -6, -4), Qt::AlignBottom | Qt::AlignLeft,
                   devices_.empty()
                       ? QString::fromUtf8("angle = subcarrier slot, radius = amplitude (not a physical bearing)")
                       : QString::fromUtf8("angle = stable per device (not a compass bearing), radius = real signal strength"));
    }

private:
    std::vector<float> amps_;
    std::vector<WifiDevice> devices_;
    double sweep_deg_ = 0.0;
    qint64 flash_started_ = 0;
};

} // namespace

QWidget* BuildWifiCsiPage(QWidget* parent) {
    (void)parent;
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(12);

    auto* title = new QLabel(QString::fromUtf8("WiFi CSI Sensing"), page);
    title->setStyleSheet("color:#ECE4DA; font-size:28px; font-weight:700; background:transparent;");
    root->addWidget(title);
    auto* sub = new QLabel(QString::fromUtf8(
        "'Quet song vo tuyen' is real and needs no extra hardware: it scans actual nearby WiFi "
        "access points (SSID/BSSID/signal strength) via Windows' Native WiFi API, plotted live "
        "on the radar by real signal strength, and flags motion/presence from real scan-to-scan "
        "RSSI fluctuation (a person moving through the signal path perturbs multipath fading). "
        "Sampling is coarse (~4s/scan) so it detects a change in the room, not precise gestures. "
        "CSI-capable card over serial is a separate, higher-resolution path with no confirmed "
        "wire format yet for a specific board. Simulated mode is a no-hardware demo of that path only."), page);
    sub->setStyleSheet("color:#8B7355; font-size:9pt; background:transparent;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    auto* ctl = new QHBoxLayout();
    ctl->setSpacing(10);
    auto* source_combo = new QComboBox(page);
    source_combo->setStyleSheet(
        "QComboBox { background:#1C1108; color:#ECE4DA; border:1px solid rgba(255,122,0,40);"
        " border-radius:8px; padding:7px 10px; font-size:9.5pt; }");
    source_combo->addItem(QString::fromUtf8("Quet song vo tuyen - real WiFi scan + motion sensing (recommended)"));
    source_combo->addItem(QString::fromUtf8("Simulated CSI (demo only, no hardware)"));
    ctl->addWidget(source_combo, 1);

    auto* refresh_btn = new QPushButton(QString::fromUtf8("Refresh ports"), page);
    refresh_btn->setCursor(Qt::PointingHandCursor);
    refresh_btn->setStyleSheet(
        "QPushButton { background:#1C1108; border:1px solid rgba(255,122,0,40); border-radius:8px;"
        " color:#FF9B3D; font-size:9.5pt; padding:8px 14px; }"
        "QPushButton:hover { background:#33261A; }");
    ctl->addWidget(refresh_btn);

    auto* baud_spin = new QSpinBox(page);
    baud_spin->setRange(1200, 921600);
    baud_spin->setValue(115200);
    baud_spin->setStyleSheet(
        "QSpinBox { background:#1C1108; color:#ECE4DA; border:1px solid rgba(255,122,0,40);"
        " border-radius:8px; padding:7px 8px; font-size:9.5pt; }");
    ctl->addWidget(baud_spin);

    auto* connect_btn = new QPushButton(QString::fromUtf8("Start"), page);
    connect_btn->setCursor(Qt::PointingHandCursor);
    connect_btn->setStyleSheet(
        "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #FF7A00);"
        " border:none; border-radius:8px; color:#fff; font-size:10pt; font-weight:700; padding:9px 22px; }"
        "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9B3D,stop:1 #FF7A00); }");
    ctl->addWidget(connect_btn);
    root->addLayout(ctl);

    auto* status = new QLabel(QString::fromUtf8("Idle."), page);
    status->setStyleSheet("color:#8B7355; font-size:9pt; background:transparent;");
    root->addWidget(status);

    auto* viz_row = new QHBoxLayout();
    viz_row->setSpacing(12);
    auto* radar = new RadarWidget(page);
    viz_row->addWidget(radar);
    auto* wave = new CsiWaveWidget(page);
    viz_row->addWidget(wave, 1);
    root->addLayout(viz_row);

    auto* events_lbl = new QLabel(QString::fromUtf8("Motion / presence events"), page);
    events_lbl->setStyleSheet("color:#8B7355; font-size:9pt; font-weight:700; background:transparent;");
    root->addWidget(events_lbl);

    auto* events_table = new QTableWidget(0, 2, page);
    events_table->setHorizontalHeaderLabels({"Time", "Event"});
    events_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    events_table->verticalHeader()->setVisible(false);
    events_table->setShowGrid(false);
    events_table->setAlternatingRowColors(true);
    events_table->setStyleSheet(
        theme::TableQss());
    events_table->horizontalHeader()->setStretchLastSection(true);
    events_table->setMaximumHeight(140);
    root->addWidget(events_table);

    auto* devices_lbl = new QLabel(QString::fromUtf8("Nearby WiFi devices (real radio scan)"), page);
    devices_lbl->setStyleSheet("color:#8B7355; font-size:9pt; font-weight:700; background:transparent;");
    root->addWidget(devices_lbl);

    auto* devices_table = new QTableWidget(0, 3, page);
    devices_table->setHorizontalHeaderLabels({"SSID", "BSSID", "Signal (dBm)"});
    devices_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    devices_table->verticalHeader()->setVisible(false);
    devices_table->setShowGrid(false);
    devices_table->setAlternatingRowColors(true);
    devices_table->setStyleSheet(
        theme::TableQss());
    devices_table->horizontalHeader()->setStretchLastSection(true);
    devices_table->setMaximumHeight(140);
    root->addWidget(devices_table);

    auto* raw_log = new QPlainTextEdit(page);
    raw_log->setReadOnly(true);
    raw_log->setPlaceholderText(QString::fromUtf8("Raw lines from the serial source appear here (useful for confirming the real wire format)."));
    raw_log->setStyleSheet(
        "QPlainTextEdit { background:#1C1108; color:#8B7355; font-family:Consolas,monospace; font-size:8.5pt;"
        " border:1px solid rgba(255,122,0,20); border-radius:8px; padding:8px; }");
    raw_log->setMaximumBlockCount(300);
    raw_log->setFixedHeight(90);
    root->addWidget(raw_log);

    auto queue = std::make_shared<FrameQueue>();
    auto sim = std::make_shared<SimSource>(queue);
    auto serial = std::make_shared<std::shared_ptr<SerialSource>>(); // holder so lambda can rebind
    auto wifi_radar = std::make_shared<std::shared_ptr<WifiRadarSource>>(); // ditto
    auto running = std::make_shared<std::atomic<bool>>(false);
    auto energy_history = std::make_shared<std::deque<float>>();
    auto rssi_energy_history = std::make_shared<std::deque<float>>();

    // Shared variance-spike motion detector. Feeds off whatever "energy"
    // signal the active source produces: sum of subcarrier amplitudes for
    // Simulated/Serial-CSI, or real per-AP RSSI fluctuation for the WiFi-scan
    // mode (see below) -- same statistical test, different real signal.
    auto checkMotion = [events_table, radar](std::deque<float>& hist, float energy,
                                              int min_samples, int max_samples,
                                              double rel_thresh, double abs_thresh,
                                              const QString& reason) {
        hist.push_back(energy);
        if (static_cast<int>(hist.size()) > max_samples) hist.pop_front();
        if (static_cast<int>(hist.size()) < min_samples) return;
        double mean = 0;
        for (float e : hist) mean += e;
        mean /= hist.size();
        double var = 0;
        for (float e : hist) var += (e - mean) * (e - mean);
        var /= hist.size();
        const double stddev = std::sqrt(var);
        if (stddev > (mean * rel_thresh + abs_thresh)) {
            const int row = events_table->rowCount();
            events_table->insertRow(row);
            events_table->setItem(row, 0, new QTableWidgetItem(
                QDateTime::currentDateTime().toString("HH:mm:ss")));
            events_table->setItem(row, 1, new QTableWidgetItem(reason));
            radar->Flash();
            hist.clear(); // avoid re-triggering every tick through the same burst
        }
    };

    auto listPorts = [refresh_btn, source_combo]() {
        // Indices 0/1 are the two fixed entries (WiFi-scan, Simulated); only
        // COM-port entries (index 2+) get refreshed here. This used to be
        // `count() > 1`, which deleted one of the two fixed entries on every
        // call (including the very first, at page load) -- a real bug, not
        // cosmetic, since it silently removed the WiFi-scan option.
        while (source_combo->count() > 2) source_combo->removeItem(2);
        for (int n = 1; n <= 32; ++n) {
            const std::string path = "\\\\.\\COM" + std::to_string(n);
            HANDLE h = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                    OPEN_EXISTING, 0, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
                source_combo->addItem(QString::fromUtf8("COM") + QString::number(n));
            }
        }
    };
    QObject::connect(refresh_btn, &QPushButton::clicked, page, listPorts);
    listPorts();

    QObject::connect(connect_btn, &QPushButton::clicked, page,
            [=]() mutable {
        if (running->load()) {
            // Stop.
            sim->Stop();
            if (*serial) { (*serial)->Stop(); serial->reset(); }
            if (*wifi_radar) { (*wifi_radar)->Stop(); wifi_radar->reset(); }
            running->store(false);
            connect_btn->setText(QString::fromUtf8("Start"));
            status->setText(QString::fromUtf8("Stopped."));
            return;
        }

        const QString choice = source_combo->currentText();
        events_table->setRowCount(0);
        devices_table->setRowCount(0);
        energy_history->clear();
        rssi_energy_history->clear();
        radar->SetFrame({});

        if (choice.startsWith("Simulated")) {
            sim->Start();
            status->setText(QString::fromUtf8("Simulated data - no device connected."));
        } else if (choice.startsWith("Quet song vo tuyen")) {
            // Real motion sensing with zero extra hardware: track each AP's
            // real RSSI across successive scans. A person moving through the
            // signal path between this machine and a nearby AP perturbs
            // multipath fading, which shows up as an RSSI swing -- this is
            // the same variance-spike test as the CSI path, just fed by a
            // real (if coarse, ~4s-per-sample) signal instead of a simulated
            // or unconfirmed-hardware one.
            auto prev_rssi = std::make_shared<std::map<std::string, int>>();
            auto src = std::make_shared<WifiRadarSource>(
                    [radar, devices_table, status, rssi_energy_history, checkMotion, prev_rssi]
                    (std::vector<WifiDevice> devices) {
                QMetaObject::invokeMethod(radar,
                        [radar, devices_table, status, devices, rssi_energy_history, checkMotion, prev_rssi]() {
                    radar->SetDevices(devices);
                    devices_table->setRowCount(0);
                    float delta_energy = 0.0f;
                    int matched = 0;
                    std::map<std::string, int> cur_rssi;
                    for (const auto& d : devices) {
                        const int row = devices_table->rowCount();
                        devices_table->insertRow(row);
                        devices_table->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(d.ssid)));
                        devices_table->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(d.bssid)));
                        devices_table->setItem(row, 2, new QTableWidgetItem(QString::number(d.rssi_dbm)));
                        cur_rssi[d.bssid] = d.rssi_dbm;
                        auto it = prev_rssi->find(d.bssid);
                        if (it != prev_rssi->end()) {
                            delta_energy += std::abs(d.rssi_dbm - it->second);
                            ++matched;
                        }
                    }
                    *prev_rssi = std::move(cur_rssi);
                    status->setText(QString::fromUtf8("Scanning radio spectrum... %1 device(s) seen last scan.")
                        .arg(devices.size()));
                    // Need at least one scan-over-scan comparison before this means anything.
                    if (matched > 0) {
                        checkMotion(*rssi_energy_history, delta_energy, 5, 15, 0.6, 3.0,
                            QString::fromUtf8("Motion / presence detected (real WiFi RSSI fluctuation)"));
                    }
                }, Qt::QueuedConnection);
            });
            src->Start();
            *wifi_radar = src;
            status->setText(QString::fromUtf8("Scanning radio spectrum..."));
        } else {
            auto src = std::make_shared<SerialSource>(queue, choice.toStdString(), baud_spin->value());
            std::string err;
            if (!src->Start(&err)) {
                status->setText(QString::fromUtf8("Error: ") + QString::fromStdString(err));
                return;
            }
            *serial = src;
            status->setText(QString::fromUtf8("Connected to ") + choice + QString::fromUtf8(", baud=") + QString::number(baud_spin->value()));
        }
        running->store(true);
        connect_btn->setText(QString::fromUtf8("Stop"));
    });

    auto* sweep = new QTimer(page);
    sweep->setInterval(30);
    auto sweep_deg = std::make_shared<double>(0.0);
    QObject::connect(sweep, &QTimer::timeout, page, [radar, sweep_deg]() {
        *sweep_deg = std::fmod(*sweep_deg + 4.0, 360.0);
        radar->SetSweepAngle(*sweep_deg);
    });
    sweep->start();

    auto* drain = new QTimer(page);
    drain->setInterval(50);
    QObject::connect(drain, &QTimer::timeout, page,
            [queue, wave, radar, raw_log, energy_history, running, checkMotion]() {
        if (!running->load()) return;
        CsiFrame f;
        int drained = 0;
        while (queue->Pop(f) && drained < 20) {
            ++drained;
            wave->SetFrame(f.amplitudes);
            radar->SetFrame(f.amplitudes);
            if (!f.raw_line.isEmpty()) raw_log->appendPlainText(f.raw_line);

            float energy = 0.0f;
            for (float a : f.amplitudes) energy += a;
            // Threshold picked empirically against the simulated burst amplitude;
            // will likely need retuning once real hardware noise floor is known.
            checkMotion(*energy_history, energy, 20, 40, 0.15, 0.5,
                        QString::fromUtf8("Motion / presence detected (signal variance spike)"));
        }
    });
    drain->start();

    return page;
}

} // namespace avdashboard
