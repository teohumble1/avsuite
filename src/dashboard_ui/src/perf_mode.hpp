#pragma once

// Runtime hardware-capability gate. Lets the UI drop the most expensive
// per-frame effects (60fps shimmer, drop shadows, long slide/fade animations)
// on low-end or old machines so the app stays smooth on Win10/11 across all
// hardware, while keeping the full experience on capable machines.

namespace avdashboard {

// True on low-end/old hardware (few cores, little RAM, or a weak/old/integrated
// GPU with little dedicated VRAM). Detected once on first call and cached.
bool IsLowEndSystem();

// Animation duration for the current machine: 0 (instant, no animation) on
// low-end, otherwise the passed value. Feed setDuration() through this.
int AnimMs(int normal_ms);

} // namespace avdashboard
