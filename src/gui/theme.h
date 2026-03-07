#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace Theme {

// ---- Clean white/light color palette ----
constexpr COLORREF BG_WINDOW     = RGB(243, 243, 243);  // Window background
constexpr COLORREF BG_WHITE      = RGB(255, 255, 255);  // Pure white panels
constexpr COLORREF BG_CONTENT    = RGB(255, 255, 255);  // Content area
constexpr COLORREF BG_ALT_ROW    = RGB(248, 249, 252);  // Alternating row
constexpr COLORREF BG_HOVER      = RGB(232, 240, 254);  // Hover state
constexpr COLORREF BG_SELECTED   = RGB(210, 228, 254);  // Selected items
constexpr COLORREF BG_HEADER     = RGB(240, 242, 245);  // Column headers
constexpr COLORREF BG_TOOLBAR    = RGB(249, 249, 251);  // Toolbar area
constexpr COLORREF BG_INPUT      = RGB(255, 255, 255);  // Input fields

constexpr COLORREF TEXT_PRIMARY   = RGB(28, 28, 36);     // Near-black
constexpr COLORREF TEXT_SECONDARY = RGB(100, 106, 120);  // Medium gray
constexpr COLORREF TEXT_DIM       = RGB(160, 164, 175);  // Light gray
constexpr COLORREF TEXT_WHITE     = RGB(255, 255, 255);  // White text on colored bg

constexpr COLORREF ACCENT         = RGB(37, 99, 235);    // Primary blue
constexpr COLORREF ACCENT_HOVER   = RGB(29, 78, 216);    // Darker blue
constexpr COLORREF ACCENT_LIGHT   = RGB(219, 234, 254);  // Very light blue

constexpr COLORREF STATUS_ALIVE   = RGB(16, 185, 129);   // Green
constexpr COLORREF STATUS_DEAD    = RGB(239, 68, 68);    // Red
constexpr COLORREF STATUS_CHECK   = RGB(245, 158, 11);   // Amber
constexpr COLORREF STATUS_UNKNOWN = RGB(156, 163, 175);  // Gray

constexpr COLORREF BORDER         = RGB(226, 228, 233);  // Light border
constexpr COLORREF BORDER_LIGHT   = RGB(240, 241, 243);  // Subtle border

constexpr COLORREF STATUSBAR_BG     = RGB(37, 99, 235);  // Blue bar
constexpr COLORREF STATUSBAR_ACTIVE = RGB(16, 163, 92);  // Green when routing

constexpr COLORREF TAB_ACTIVE_BG    = RGB(255, 255, 255);
constexpr COLORREF TAB_INACTIVE_BG  = RGB(243, 243, 243);

// ---- GDI objects ----
extern HBRUSH hbr_window;
extern HBRUSH hbr_white;
extern HBRUSH hbr_content;
extern HBRUSH hbr_alt_row;
extern HBRUSH hbr_selected;
extern HBRUSH hbr_header;
extern HBRUSH hbr_toolbar;
extern HBRUSH hbr_input;
extern HFONT  hfont_ui;
extern HFONT  hfont_ui_bold;
extern HFONT  hfont_mono;
extern HFONT  hfont_title;

void init();
void cleanup();

// Fill rect with solid color
void fill_rect(HDC hdc, const RECT& rc, COLORREF color);

// Get proxy status color
COLORREF proxy_status_color(int status);

// Light-theme color handler for dialog controls
LRESULT handle_ctl_color(UINT msg, WPARAM wParam);

} // namespace Theme
