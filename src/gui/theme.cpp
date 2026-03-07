#include "gui/theme.h"

namespace Theme {

HBRUSH hbr_window   = nullptr;
HBRUSH hbr_white    = nullptr;
HBRUSH hbr_content  = nullptr;
HBRUSH hbr_alt_row  = nullptr;
HBRUSH hbr_selected = nullptr;
HBRUSH hbr_header   = nullptr;
HBRUSH hbr_toolbar  = nullptr;
HBRUSH hbr_input    = nullptr;
HFONT  hfont_ui      = nullptr;
HFONT  hfont_ui_bold = nullptr;
HFONT  hfont_mono    = nullptr;
HFONT  hfont_title   = nullptr;

void init() {
    hbr_window   = CreateSolidBrush(BG_WINDOW);
    hbr_white    = CreateSolidBrush(BG_WHITE);
    hbr_content  = CreateSolidBrush(BG_CONTENT);
    hbr_alt_row  = CreateSolidBrush(BG_ALT_ROW);
    hbr_selected = CreateSolidBrush(BG_SELECTED);
    hbr_header   = CreateSolidBrush(BG_HEADER);
    hbr_toolbar  = CreateSolidBrush(BG_TOOLBAR);
    hbr_input    = CreateSolidBrush(BG_INPUT);

    hfont_ui = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    hfont_ui_bold = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    hfont_mono = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");
    hfont_title = CreateFontW(-16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
}

void cleanup() {
    auto del = [](HGDIOBJ& obj) { if (obj) { DeleteObject(obj); obj = nullptr; } };
    del((HGDIOBJ&)hbr_window);   del((HGDIOBJ&)hbr_white);
    del((HGDIOBJ&)hbr_content);  del((HGDIOBJ&)hbr_alt_row);
    del((HGDIOBJ&)hbr_selected); del((HGDIOBJ&)hbr_header);
    del((HGDIOBJ&)hbr_toolbar);  del((HGDIOBJ&)hbr_input);
    del((HGDIOBJ&)hfont_ui);     del((HGDIOBJ&)hfont_ui_bold);
    del((HGDIOBJ&)hfont_mono);   del((HGDIOBJ&)hfont_title);
}

void fill_rect(HDC hdc, const RECT& rc, COLORREF color) {
    HBRUSH brush = CreateSolidBrush(color);
    FillRect(hdc, &rc, brush);
    DeleteObject(brush);
}

COLORREF proxy_status_color(int status) {
    switch (status) {
        case 2: return STATUS_ALIVE;
        case 3: return STATUS_DEAD;
        case 1: return STATUS_CHECK;
        default: return STATUS_UNKNOWN;
    }
}

LRESULT handle_ctl_color(UINT msg, WPARAM wParam) {
    HDC hdc = (HDC)wParam;
    switch (msg) {
    case WM_CTLCOLORDLG:
        return (LRESULT)hbr_white;
    case WM_CTLCOLORSTATIC:
        SetTextColor(hdc, TEXT_PRIMARY);
        SetBkColor(hdc, BG_WHITE);
        return (LRESULT)hbr_white;
    case WM_CTLCOLOREDIT:
        SetTextColor(hdc, TEXT_PRIMARY);
        SetBkColor(hdc, BG_INPUT);
        return (LRESULT)hbr_input;
    case WM_CTLCOLORLISTBOX:
        SetTextColor(hdc, TEXT_PRIMARY);
        SetBkColor(hdc, BG_WHITE);
        return (LRESULT)hbr_white;
    }
    return 0;
}

} // namespace Theme
