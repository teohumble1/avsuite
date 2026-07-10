#pragma once

// AvSuite dashboard design tokens.
//
// These values are the single source of truth for the dashboard's visual system,
// ported verbatim from the Figma "Antivirus Dashboard Redesign" (its `T` token
// object and `theme.css` variables). Pages should reference these constants and
// the helpers below instead of hardcoding hex colors / pixel radii, so the UI
// stays consistent as it is refactored tab by tab.

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QString>
#include <QVBoxLayout>
#include <QWidget>

namespace theme {

// ── Color (exact Figma tokens) ──────────────────────────────────────────────
inline constexpr const char* Bg         = "#120B06"; // app ground
inline constexpr const char* Surface    = "#1C1108"; // card / panel
inline constexpr const char* Surface2   = "#241708"; // raised row / input
inline constexpr const char* Sidebar    = "#0E0804"; // nav rail (darker)
inline constexpr const char* Border     = "#33261A"; // hairline
inline constexpr const char* Text        = "#ECE4DA"; // primary text
inline constexpr const char* Muted       = "#C7B6A2"; // secondary text
inline constexpr const char* Dim         = "#8B7355"; // captions / disabled
inline constexpr const char* Accent      = "#FF7A00"; // brand amber
inline constexpr const char* AccentSoft  = "#FF9B3D"; // hover / lighter accent
// Semantic (map to detection severity)
inline constexpr const char* Safe        = "#4ADE80"; // clean / safe / signed / allow / pass
inline constexpr const char* Warn        = "#FBBF24"; // suspicious
inline constexpr const char* Danger      = "#FF5A6A"; // malicious / unsigned / block
inline constexpr const char* Info        = "#4DB8FF"; // neutral / info

// Fonts
inline constexpr const char* SansFamily = "'Inter', 'Segoe UI', system-ui, sans-serif";
inline constexpr const char* MonoFamily = "'Cascadia Code', Consolas, ui-monospace, monospace";

// ── Radius (px) — pick from these three, plus pill ──────────────────────────
inline constexpr int RadiusSm   = 4;   // chips, inputs
inline constexpr int RadiusMd   = 8;   // buttons, cells
inline constexpr int RadiusLg   = 14;  // cards, panels
inline constexpr int RadiusPill = 999; // badges

// ── Type scale (px) ─────────────────────────────────────────────────────────
inline constexpr int FontCaption = 12;
inline constexpr int FontBody    = 14;
inline constexpr int FontSubhead = 16;
inline constexpr int FontTitle   = 20;
inline constexpr int FontHeader  = 28;

// ── Spacing (px, 4px base) ──────────────────────────────────────────────────
inline constexpr int Space1 = 4;
inline constexpr int Space2 = 8;
inline constexpr int Space3 = 12;
inline constexpr int Space4 = 16;
inline constexpr int Space6 = 24;
inline constexpr int Space8 = 32;

// Maps a detection severity / status string to its semantic accent color.
inline const char* SeverityColor(const QString& severity) {
    const QString s = severity.trimmed().toLower();
    if (s == "malicious" || s == "unsigned" || s == "block" || s == "fail" || s == "critical")
        return Danger;
    if (s == "suspicious" || s == "warn" || s == "warning")
        return Warn;
    if (s == "safe" || s == "clean" || s == "signed" || s == "allow" || s == "pass" || s == "ok")
        return Safe;
    return Info;
}

// Extra component stylesheet, layered ON TOP of the app's base stylesheet.
// Every selector targets an objectName that a page must opt into (e.g. a QLabel
// named "PageHeaderTitle"), so this never restyles existing widgets — pages
// adopt it incrementally.
inline QString ComponentQss() {
    return QString(R"QSS(
        QLabel#PageHeaderTitle    { color: %1; font-size: %2px; font-weight: 600; }
        QLabel#PageHeaderSubtitle { color: %3; font-size: %4px; }

        QFrame#Card {
            background: %5;
            border: 1px solid %6;
            border-radius: %7px;
        }

        QPushButton#PrimaryBtn {
            background: %8; color: %9;
            border: none; border-radius: %10px;
            padding: 8px 16px; font-weight: 600;
        }
        QPushButton#PrimaryBtn:hover    { background: %11; }
        QPushButton#PrimaryBtn:disabled { background: %6; color: %12; }

        QPushButton#GhostBtn {
            background: transparent; color: %1;
            border: 1px solid %6; border-radius: %10px;
            padding: 8px 16px;
        }
        QPushButton#GhostBtn:hover { border-color: %8; color: %8; }

        QPushButton#DangerBtn {
            background: transparent; color: %13;
            border: 1px solid %13; border-radius: %10px;
            padding: 8px 16px; font-weight: 600;
        }
        QPushButton#DangerBtn:hover { background: rgba(255,90,106,0.12); }
    )QSS")
        .arg(Text)          // %1
        .arg(FontHeader)    // %2
        .arg(Muted)         // %3
        .arg(FontBody)      // %4
        .arg(Surface)       // %5
        .arg(Border)        // %6
        .arg(RadiusLg)      // %7
        .arg(Accent)        // %8
        .arg(Bg)            // %9
        .arg(RadiusMd)      // %10
        .arg(AccentSoft)    // %11
        .arg(Dim)           // %12
        .arg(Danger);       // %13
}

// Builds the standard page header: a title, an optional one-line subtitle, and
// an optional right-aligned action widget (button, search, etc). Reused by every
// page so titles/spacing stay identical across tabs.
inline QWidget* BuildPageHeader(const QString& title,
                                const QString& subtitle = QString(),
                                QWidget* action = nullptr) {
    auto* header = new QWidget();
    auto* row = new QHBoxLayout(header);
    row->setContentsMargins(0, 0, 0, Space4);
    row->setSpacing(Space4);

    auto* textCol = new QVBoxLayout();
    textCol->setSpacing(2);
    auto* titleLbl = new QLabel(title);
    titleLbl->setObjectName("PageHeaderTitle");
    textCol->addWidget(titleLbl);
    if (!subtitle.isEmpty()) {
        auto* subLbl = new QLabel(subtitle);
        subLbl->setObjectName("PageHeaderSubtitle");
        subLbl->setWordWrap(true);
        textCol->addWidget(subLbl);
    }
    row->addLayout(textCol);
    row->addStretch();
    if (action) row->addWidget(action);

    return header;
}

} // namespace theme
