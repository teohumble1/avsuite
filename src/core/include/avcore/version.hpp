#pragma once

namespace avcore {

// Single source of truth for the app's own version, compared against
// avupdateserver's manifest.json "app_latest_version" field by the
// Self-Update page. Bump this alongside installer.iss's AppVersion when
// cutting a release.
inline constexpr const char* kAppVersion = "1.0.5";

} // namespace avcore
