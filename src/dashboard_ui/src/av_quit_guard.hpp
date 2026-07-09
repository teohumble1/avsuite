// av_quit_guard.hpp — shared "app is quitting" flag for background scan threads.
//
// Several pages (LAN Monitor, DLP, Supply-chain, Hidden Hunt, OSINT, ...) run
// a scan on a detached std::thread and, when it finishes, touch page widgets
// via QMetaObject::invokeMethod. If the app is closed while that scan is
// still running, the widgets are already destroyed by the time the thread
// gets there -- invokeMethod(dangling_widget, ...) dereferences freed memory
// and crashes. Root-caused in main_window_lanmonitor.cpp; this header lets
// every page share one flag instead of each re-declaring its own.
//
// Usage: call ArmQuitGuard(page) once when building the page, then have the
// background thread check AppQuitting() before each widget touch (and
// ideally between long-running steps too, to bail out promptly) instead of
// running to completion regardless.
#pragma once

#include <QCoreApplication>
#include <QObject>
#include <QWidget>

#include <atomic>

namespace avdashboard {

inline std::atomic<bool>& AppQuitting() {
    static std::atomic<bool> flag{false};
    return flag;
}

// Safe to call once per page; QCoreApplication::aboutToQuit fires for every
// connected receiver, so multiple pages each arming this is fine.
inline void ArmQuitGuard(QWidget* page) {
    QObject::connect(qApp, &QCoreApplication::aboutToQuit, page,
                      [] { AppQuitting().store(true); });
}

} // namespace avdashboard
