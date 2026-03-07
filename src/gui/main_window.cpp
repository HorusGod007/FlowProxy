#include "gui/main_window.h"
#include "gui/dialogs.h"
#include "gui/theme.h"
#include "resources/resource.h"

#include <commdlg.h>
#include <windowsx.h>
#include <uxtheme.h>
#include <cstdio>
#include <sstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

static const wchar_t* CLASS_NAME = L"FlowProxyMain";
static const wchar_t* WINDOW_TITLE = L"FlowProxy";

MainWindow::MainWindow() {
    server_ = new LocalProxyServer(proxy_list_);
    interceptor_ = new TrafficInterceptor(proxy_list_, rules_engine_,
                                          chain_manager_, dns_resolver_, conn_monitor_);
}

MainWindow::~MainWindow() {
    if (routing_active_) SystemProxy::clear_system_proxy();
    interceptor_->stop();
    delete interceptor_;
    delete server_;
    Settings::save(settings_);
}

bool MainWindow::create(HINSTANCE hInstance, int nCmdShow) {
    hinstance_ = hInstance;
    Settings::load(settings_);

    CheckerConfig cc;
    cc.thread_count = settings_.checker_threads;
    cc.timeout_ms = settings_.checker_timeout;
    cc.test_url = settings_.test_url;
    checker_.set_config(cc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(Theme::BG_WINDOW);
    wc.lpszClassName = CLASS_NAME;
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON));
    if (!wc.hIcon) wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;

    if (!RegisterClassExW(&wc)) return false;

    // Validate saved window position is visible on some monitor
    int wx = settings_.window_x, wy = settings_.window_y;
    int ww = settings_.window_w, wh = settings_.window_h;
    if (ww < 200) ww = 1100;
    if (wh < 150) wh = 680;
    RECT test_rc = { wx, wy, wx + ww, wy + wh };
    HMONITOR hmon = MonitorFromRect(&test_rc, MONITOR_DEFAULTTONULL);
    if (!hmon) {
        wx = CW_USEDEFAULT; wy = CW_USEDEFAULT;
        ww = 1100; wh = 680;
    }

    hwnd_ = CreateWindowExW(
        0,
        CLASS_NAME, WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        wx, wy, ww, wh,
        nullptr, nullptr, hInstance, this
    );

    if (!hwnd_) return false;

    ShowWindow(hwnd_, nCmdShow);
    UpdateWindow(hwnd_);

    // Load saved data
    std::string save_path = Settings::get_proxy_save_path();
    auto proxies = ProxyImporter::import_from_file(save_path);
    for (auto& p : proxies) proxy_list_.add(p);

    std::string data_dir = save_path.substr(0, save_path.find_last_of("\\/"));
    rules_engine_.load_from_file(data_dir + "\\rules.dat");
    chain_manager_.load_from_file(data_dir + "\\chains.dat");

    refresh_proxy_list();
    refresh_rules_list();

    // Auto-start routing silently
    if (interceptor_->start(settings_.server_port, settings_.rotation_mode)) {
        interceptor_->start_socks5(settings_.server_port + 1, settings_.rotation_mode);
        SystemProxy::set_system_proxy("127.0.0.1", settings_.server_port);
        routing_active_ = true;
    }
    update_statusbar();

    return true;
}

LRESULT CALLBACK MainWindow::wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* self = nullptr;
    if (msg == WM_NCCREATE) {
        auto cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        self = reinterpret_cast<MainWindow*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->hwnd_ = hwnd;
    } else {
        self = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    if (self) return self->handle_message(msg, wParam, lParam);
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT MainWindow::handle_message(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        Theme::init();
        create_menu();
        create_tab_control();
        create_proxy_listview();
        create_rules_listview();
        create_connections_listview();
        create_logs_listview();
        create_statusbar();
        create_tray_icon();
        apply_dark_theme();
        on_tab_changed();
        update_layout();
        SetTimer(hwnd_, IDT_STATS_REFRESH, 2000, nullptr);
        SetTimer(hwnd_, IDT_RATE_UPDATE, 1000, nullptr);
        return 0;

    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) {
            minimize_to_tray();
            return 0;
        }
        update_layout();
        return 0;

    case WM_TRAY_ICON:
        on_tray_icon(lParam);
        return 0;

    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd_, &rc);
        FillRect(hdc, &rc, Theme::hbr_window);
        return 1;
    }

    case WM_DRAWITEM:
        break;

    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        LRESULT r = Theme::handle_ctl_color(msg, wParam);
        if (r) return r;
        break;
    }

    case WM_INITMENUPOPUP: {
        HMENU sub = (HMENU)wParam;
        // Enable/disable routing menu items based on state
        UINT enable_state = routing_active_ ? MF_GRAYED : MF_ENABLED;
        UINT disable_state = routing_active_ ? MF_ENABLED : MF_GRAYED;
        EnableMenuItem(sub, IDM_TOOLS_SET_SYSTEM, MF_BYCOMMAND | enable_state);
        EnableMenuItem(sub, IDM_TOOLS_CLEAR_SYSTEM, MF_BYCOMMAND | disable_state);
        return 0;
    }

    case WM_COMMAND:
        on_command(wParam);
        return 0;

    case WM_NOTIFY:
        return on_notify(lParam);

    case WM_CONTEXTMENU:
        on_context_menu((HWND)wParam, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
        return 0;

    case WM_TIMER:
        on_timer(wParam);
        return 0;

    case WM_PROXY_CHECK_UPDATE:
        update_listview_item((int)wParam);
        update_statusbar();
        return 0;

    case WM_PROXY_CHECK_DONE:
        update_statusbar();
        MessageBoxW(hwnd_, L"Proxy checking complete.", L"FlowProxy", MB_ICONINFORMATION);
        return 0;

    case WM_SERVER_STATUS:
        update_statusbar();
        return 0;

    case WM_CLOSE: {
        if (!in_tray_) {
            RECT rc;
            GetWindowRect(hwnd_, &rc);
            settings_.window_x = rc.left;
            settings_.window_y = rc.top;
            settings_.window_w = rc.right - rc.left;
            settings_.window_h = rc.bottom - rc.top;
        }
        Settings::save(settings_);

        std::string save_path = Settings::get_proxy_save_path();
        {
            std::lock_guard<std::mutex> lock(proxy_list_.mutex());
            ProxyImporter::export_to_file(save_path, proxy_list_.proxies());
        }

        std::string data_dir = save_path.substr(0, save_path.find_last_of("\\/"));
        rules_engine_.save_to_file(data_dir + "\\rules.dat");
        chain_manager_.save_to_file(data_dir + "\\chains.dat");

        KillTimer(hwnd_, IDT_STATS_REFRESH);
        KillTimer(hwnd_, IDT_RATE_UPDATE);
        checker_.stop();
        if (routing_active_) SystemProxy::clear_system_proxy();
        interceptor_->stop();
        DestroyWindow(hwnd_);
        return 0;
    }

    case WM_DESTROY:
        remove_tray_icon();
        Theme::cleanup();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd_, msg, wParam, lParam);
}

// ============================================================================
// Menu
// ============================================================================

void MainWindow::create_menu() {
    menu_ = CreateMenu();

    HMENU file_menu = CreatePopupMenu();
    AppendMenuW(file_menu, MF_STRING, IDM_FILE_IMPORT, L"&Import Proxies...\tCtrl+I");
    AppendMenuW(file_menu, MF_STRING, IDM_FILE_EXPORT, L"&Export Proxies...\tCtrl+E");
    AppendMenuW(file_menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(file_menu, MF_STRING, IDM_FILE_SETTINGS, L"&Settings...\tCtrl+S");
    AppendMenuW(file_menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(file_menu, MF_STRING, IDM_FILE_EXIT, L"E&xit\tAlt+F4");

    HMENU proxy_menu = CreatePopupMenu();
    AppendMenuW(proxy_menu, MF_STRING, IDM_PROXY_ADD, L"&Add Proxy...\tIns");
    AppendMenuW(proxy_menu, MF_STRING, IDM_PROXY_EDIT, L"&Edit Proxy...\tEnter");
    AppendMenuW(proxy_menu, MF_STRING, IDM_PROXY_DELETE, L"&Delete Selected\tDel");
    AppendMenuW(proxy_menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(proxy_menu, MF_STRING, IDM_PROXY_DELETE_ALL, L"Delete &All");
    AppendMenuW(proxy_menu, MF_STRING, IDM_PROXY_DELETE_DEAD, L"Delete Dea&d");

    HMENU check_menu = CreatePopupMenu();
    AppendMenuW(check_menu, MF_STRING, IDM_CHECK_ALL, L"Check &All");
    AppendMenuW(check_menu, MF_STRING, IDM_CHECK_SELECTED, L"Check &Selected");
    AppendMenuW(check_menu, MF_STRING, IDM_CHECK_STOP, L"S&top");

    HMENU rules_menu = CreatePopupMenu();
    AppendMenuW(rules_menu, MF_STRING, IDM_RULES_ADD, L"Add &Rule...");
    AppendMenuW(rules_menu, MF_STRING, IDM_RULES_EDIT, L"&Edit Rule...");
    AppendMenuW(rules_menu, MF_STRING, IDM_RULES_DELETE, L"&Delete Rule");
    AppendMenuW(rules_menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(rules_menu, MF_STRING, IDM_CHAIN_ADD, L"Add &Chain...");
    AppendMenuW(rules_menu, MF_STRING, IDM_CHAIN_EDIT, L"Edit C&hain...");
    AppendMenuW(rules_menu, MF_STRING, IDM_CHAIN_DELETE, L"Delete Chai&n");

    HMENU tools_menu = CreatePopupMenu();
    AppendMenuW(tools_menu, MF_STRING, IDM_TOOLS_SET_SYSTEM, L"&Enable Routing");
    AppendMenuW(tools_menu, MF_STRING, IDM_TOOLS_CLEAR_SYSTEM, L"&Disable Routing");
    AppendMenuW(tools_menu, MF_SEPARATOR, 0, nullptr);
    HMENU dns_sub = CreatePopupMenu();
    AppendMenuW(dns_sub, MF_STRING, IDM_DNS_LOCAL, L"&Local DNS");
    AppendMenuW(dns_sub, MF_STRING, IDM_DNS_REMOTE, L"&Remote DNS (via proxy)");
    AppendMenuW(dns_sub, MF_STRING, IDM_DNS_CUSTOM, L"&Custom DNS");
    AppendMenuW(dns_sub, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(dns_sub, MF_STRING, IDM_DNS_FLUSH_CACHE, L"&Flush DNS Cache");
    AppendMenuW(tools_menu, MF_POPUP, (UINT_PTR)dns_sub, L"D&NS");

    HMENU view_menu = CreatePopupMenu();
    AppendMenuW(view_menu, MF_STRING, IDM_VIEW_STATS, L"Traffic &Statistics...");
    AppendMenuW(view_menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(view_menu, MF_STRING, IDM_VIEW_EXPORT_LOGS, L"&Export Logs (CSV)...");
    AppendMenuW(view_menu, MF_STRING, IDM_VIEW_CLEAR_LOGS, L"&Clear Logs");

    HMENU help_menu = CreatePopupMenu();
    AppendMenuW(help_menu, MF_STRING, IDM_HELP_ABOUT, L"&About FlowProxy...");

    AppendMenuW(menu_, MF_POPUP, (UINT_PTR)file_menu, L"&File");
    AppendMenuW(menu_, MF_POPUP, (UINT_PTR)proxy_menu, L"&Proxy");
    AppendMenuW(menu_, MF_POPUP, (UINT_PTR)check_menu, L"&Check");
    AppendMenuW(menu_, MF_POPUP, (UINT_PTR)rules_menu, L"&Rules");
    AppendMenuW(menu_, MF_POPUP, (UINT_PTR)tools_menu, L"&Tools");
    AppendMenuW(menu_, MF_POPUP, (UINT_PTR)view_menu, L"&View");
    AppendMenuW(menu_, MF_POPUP, (UINT_PTR)help_menu, L"&Help");

    SetMenu(hwnd_, menu_);
}

// ============================================================================
// Toolbar
// ============================================================================

void MainWindow::create_toolbar() {
    toolbar_ = CreateWindowExW(
        0, TOOLBARCLASSNAMEW, nullptr,
        WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_LIST | TBSTYLE_TOOLTIPS | CCS_NODIVIDER,
        0, 0, 0, 0,
        hwnd_, (HMENU)IDT_TOOLBAR, hinstance_, nullptr
    );

    SendMessage(toolbar_, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    SendMessage(toolbar_, TB_SETBITMAPSIZE, 0, MAKELONG(0, 0));
    SendMessage(toolbar_, WM_SETFONT, (WPARAM)Theme::hfont_ui, TRUE);
    SendMessage(toolbar_, TB_SETPADDING, 0, MAKELONG(16, 8));

    TBBUTTON buttons[] = {
        { -1, IDB_ADD,       TBSTATE_ENABLED, BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT, {0}, 0, (INT_PTR)L"  Add  " },
        { -1, IDB_DELETE,    TBSTATE_ENABLED, BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT, {0}, 0, (INT_PTR)L"  Delete  " },
        { 0,  0,             TBSTATE_ENABLED, BTNS_SEP, {0}, 0, 0 },
        { -1, IDB_CHECK_ALL, TBSTATE_ENABLED, BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT, {0}, 0, (INT_PTR)L"  Check All  " },
        { -1, IDB_CHECK_SEL, TBSTATE_ENABLED, BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT, {0}, 0, (INT_PTR)L"  Check Selected  " },
        { -1, IDB_STOP,      TBSTATE_ENABLED, BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT, {0}, 0, (INT_PTR)L"  Stop  " },
        { 0,  0,             TBSTATE_ENABLED, BTNS_SEP, {0}, 0, 0 },
        { -1, IDB_IMPORT,    TBSTATE_ENABLED, BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT, {0}, 0, (INT_PTR)L"  Import  " },
        { -1, IDB_EXPORT,    TBSTATE_ENABLED, BTNS_BUTTON | BTNS_AUTOSIZE | BTNS_SHOWTEXT, {0}, 0, (INT_PTR)L"  Export  " },
    };

    SendMessage(toolbar_, TB_ADDBUTTONS, _countof(buttons), (LPARAM)buttons);
    SendMessage(toolbar_, TB_AUTOSIZE, 0, 0);
}

// ============================================================================
// Tab Control + ListViews
// ============================================================================

void MainWindow::create_tab_control() {
    tab_control_ = CreateWindowExW(
        0, WC_TABCONTROLW, L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0, 0, 0, 0,
        hwnd_, (HMENU)IDC_TAB_CONTROL, hinstance_, nullptr
    );

    SendMessage(tab_control_, WM_SETFONT, (WPARAM)Theme::hfont_ui, TRUE);

    const wchar_t* tabs[] = { L"  Proxies  ", L"  Rules  ", L"  Connections  ", L"  Logs  " };
    for (int i = 0; i < 4; ++i) {
        TCITEMW ti = {};
        ti.mask = TCIF_TEXT;
        ti.pszText = (LPWSTR)tabs[i];
        TabCtrl_InsertItem(tab_control_, i, &ti);
    }
}

static HWND create_lv(HWND parent, HINSTANCE hInst, int id) {
    HWND lv = CreateWindowExW(
        0, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS,
        0, 0, 0, 0,
        parent, (HMENU)(INT_PTR)id, hInst, nullptr
    );
    ListView_SetExtendedListViewStyle(lv,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
    ListView_SetBkColor(lv, Theme::BG_WHITE);
    ListView_SetTextBkColor(lv, Theme::BG_WHITE);
    ListView_SetTextColor(lv, Theme::TEXT_PRIMARY);
    SetWindowTheme(lv, L"Explorer", nullptr);
    SendMessage(lv, WM_SETFONT, (WPARAM)Theme::hfont_ui, TRUE);
    return lv;
}

void MainWindow::create_proxy_listview() {
    lv_proxies_ = create_lv(hwnd_, hinstance_, IDC_LISTVIEW);
    struct { const wchar_t* n; int w; } cols[] = {
        {L"#",42},{L"Host",175},{L"Port",60},{L"Type",70},{L"Status",75},
        {L"Latency",70},{L"Anonymity",85},{L"Country",70},{L"Last Check",135}
    };
    for (int i = 0; i < _countof(cols); ++i) {
        LVCOLUMNW c = {}; c.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
        c.iSubItem = i; c.pszText = (LPWSTR)cols[i].n; c.cx = cols[i].w;
        ListView_InsertColumn(lv_proxies_, i, &c);
    }
}

void MainWindow::create_rules_listview() {
    lv_rules_ = create_lv(hwnd_, hinstance_, IDC_LV_RULES);
    struct { const wchar_t* n; int w; } cols[] = {
        {L"#",38},{L"Enabled",60},{L"Name",135},{L"Target",90},{L"Pattern",175},
        {L"Action",85},{L"Proxy/Chain",110},{L"Priority",65}
    };
    for (int i = 0; i < _countof(cols); ++i) {
        LVCOLUMNW c = {}; c.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
        c.iSubItem = i; c.pszText = (LPWSTR)cols[i].n; c.cx = cols[i].w;
        ListView_InsertColumn(lv_rules_, i, &c);
    }
}

void MainWindow::create_connections_listview() {
    lv_connections_ = CreateWindowExW(
        0, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_NOSORTHEADER,
        0, 0, 0, 0,
        hwnd_, (HMENU)(INT_PTR)IDC_LV_CONNECTIONS, hinstance_, nullptr
    );
    ListView_SetExtendedListViewStyle(lv_connections_,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
    ListView_SetBkColor(lv_connections_, Theme::BG_WHITE);
    ListView_SetTextBkColor(lv_connections_, Theme::BG_WHITE);
    ListView_SetTextColor(lv_connections_, Theme::TEXT_PRIMARY);
    SetWindowTheme(lv_connections_, L"Explorer", nullptr);
    SendMessage(lv_connections_, WM_SETFONT, (WPARAM)Theme::hfont_ui, TRUE);
    struct { const wchar_t* n; int w; } cols[] = {
        {L"Application",130},{L"PID",55},{L"Local Address",120},{L"Local Port",65},
        {L"Remote Address",130},{L"Remote Port",75},{L"State",90},{L"Proxied",55}
    };
    for (int i = 0; i < _countof(cols); ++i) {
        LVCOLUMNW c = {}; c.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
        c.iSubItem = i; c.pszText = (LPWSTR)cols[i].n; c.cx = cols[i].w;
        ListView_InsertColumn(lv_connections_, i, &c);
    }
}

void MainWindow::create_logs_listview() {
    lv_logs_ = CreateWindowExW(
        0, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_NOSORTHEADER,
        0, 0, 0, 0,
        hwnd_, (HMENU)(INT_PTR)IDC_LV_LOGS, hinstance_, nullptr
    );
    ListView_SetExtendedListViewStyle(lv_logs_,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
    ListView_SetBkColor(lv_logs_, Theme::BG_WHITE);
    ListView_SetTextBkColor(lv_logs_, Theme::BG_WHITE);
    ListView_SetTextColor(lv_logs_, Theme::TEXT_PRIMARY);
    SetWindowTheme(lv_logs_, L"Explorer", nullptr);
    SendMessage(lv_logs_, WM_SETFONT, (WPARAM)Theme::hfont_ui, TRUE);
    struct { const wchar_t* n; int w; } cols[] = {
        {L"Time",135},{L"App",100},{L"Destination",155},{L"Port",50},{L"Proxy",120},
        {L"Method",65},{L"Status",55},{L"Sent",65},{L"Recv",65},{L"Rule",100},{L"Error",110}
    };
    for (int i = 0; i < _countof(cols); ++i) {
        LVCOLUMNW c = {}; c.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
        c.iSubItem = i; c.pszText = (LPWSTR)cols[i].n; c.cx = cols[i].w;
        ListView_InsertColumn(lv_logs_, i, &c);
    }
}

void MainWindow::create_statusbar() {
    statusbar_ = CreateWindowExW(
        0, STATUSCLASSNAMEW, L"",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        hwnd_, (HMENU)IDS_STATUSBAR, hinstance_, nullptr
    );
    SendMessage(statusbar_, WM_SETFONT, (WPARAM)Theme::hfont_ui, TRUE);
    SendMessage(statusbar_, SB_SETMINHEIGHT, 24, 0);
    int parts[] = { 220, 440, -1 };
    SendMessage(statusbar_, SB_SETPARTS, 3, (LPARAM)parts);
    update_statusbar();
}

void MainWindow::update_layout() {
    SendMessage(statusbar_, WM_SIZE, 0, 0);

    RECT rc, status_rc;
    GetClientRect(hwnd_, &rc);
    GetWindowRect(statusbar_, &status_rc);
    int sh = status_rc.bottom - status_rc.top;

    int content_y = 0;
    int content_h = rc.bottom - sh;

    MoveWindow(tab_control_, 0, content_y, rc.right, content_h, TRUE);

    RECT tab_rc = { 0, 0, rc.right, content_h };
    TabCtrl_AdjustRect(tab_control_, FALSE, &tab_rc);

    int lx = tab_rc.left, ly = content_y + tab_rc.top;
    int lw = tab_rc.right - tab_rc.left, lh = tab_rc.bottom - tab_rc.top;

    HWND lists[] = { lv_proxies_, lv_rules_, lv_connections_, lv_logs_ };
    for (auto lv : lists) {
        MoveWindow(lv, lx, ly, lw, lh, TRUE);
    }
}

void MainWindow::on_tab_changed() {
    current_tab_ = TabCtrl_GetCurSel(tab_control_);
    HWND lists[] = { lv_proxies_, lv_rules_, lv_connections_, lv_logs_ };
    for (int i = 0; i < 4; ++i) {
        ShowWindow(lists[i], (i == current_tab_) ? SW_SHOW : SW_HIDE);
    }
    if (current_tab_ == 2) refresh_connections_list();
    if (current_tab_ == 3) refresh_logs_list();
}

// ============================================================================
// Refresh functions
// ============================================================================

static std::wstring format_bytes(uint64_t bytes) {
    if (bytes < 1024) return std::to_wstring(bytes) + L" B";
    if (bytes < 1024 * 1024) return std::to_wstring(bytes / 1024) + L" KB";
    if (bytes < 1024ULL * 1024 * 1024) return std::to_wstring(bytes / (1024 * 1024)) + L" MB";
    return std::to_wstring(bytes / (1024ULL * 1024 * 1024)) + L" GB";
}

void MainWindow::refresh_proxy_list() {
    std::vector<Proxy> proxies_copy;
    {
        std::lock_guard<std::mutex> lock(proxy_list_.mutex());
        proxies_copy = proxy_list_.proxies();
    }

    SendMessage(lv_proxies_, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(lv_proxies_);
    for (size_t i = 0; i < proxies_copy.size(); ++i) {
        const Proxy& p = proxies_copy[i];
        LVITEMW item = {}; item.mask = LVIF_TEXT; item.iItem = (int)i;
        std::wstring num = std::to_wstring(i + 1);
        item.pszText = (LPWSTR)num.c_str();
        ListView_InsertItem(lv_proxies_, &item);
        std::wstring h = utf8_to_wide(p.host);
        ListView_SetItemText(lv_proxies_,(int)i,1,(LPWSTR)h.c_str());
        std::wstring po = std::to_wstring(p.port);
        ListView_SetItemText(lv_proxies_,(int)i,2,(LPWSTR)po.c_str());
        ListView_SetItemText(lv_proxies_,(int)i,3,(LPWSTR)proxy_type_to_wstr(p.type));
        ListView_SetItemText(lv_proxies_,(int)i,4,(LPWSTR)proxy_status_to_wstr(p.status));
        std::wstring lat = (p.latency_ms>=0)?std::to_wstring(p.latency_ms)+L" ms":L"-";
        ListView_SetItemText(lv_proxies_,(int)i,5,(LPWSTR)lat.c_str());
        ListView_SetItemText(lv_proxies_,(int)i,6,(LPWSTR)anonymity_to_wstr(p.anonymity));
        std::wstring co = utf8_to_wide(p.country);
        ListView_SetItemText(lv_proxies_,(int)i,7,(LPWSTR)co.c_str());
        std::wstring lc = L"-";
        if (p.last_checked > 0) {
            wchar_t tb[64]; struct tm ti; localtime_s(&ti,&p.last_checked);
            wcsftime(tb,64,L"%Y-%m-%d %H:%M:%S",&ti); lc = tb;
        }
        ListView_SetItemText(lv_proxies_,(int)i,8,(LPWSTR)lc.c_str());
    }
    SendMessage(lv_proxies_, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(lv_proxies_, nullptr, TRUE);
}

void MainWindow::refresh_rules_list() {
    SendMessage(lv_rules_, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(lv_rules_);
    for (size_t i = 0; i < rules_engine_.rule_count(); ++i) {
        const auto& r = rules_engine_.rule_at(i);
        LVITEMW item = {}; item.mask = LVIF_TEXT; item.iItem = (int)i;
        std::wstring num = std::to_wstring(i + 1);
        item.pszText = (LPWSTR)num.c_str();
        ListView_InsertItem(lv_rules_, &item);

        ListView_SetItemText(lv_rules_,(int)i,1,(LPWSTR)(r.enabled?L"Yes":L"No"));
        std::wstring nm = utf8_to_wide(r.name);
        ListView_SetItemText(lv_rules_,(int)i,2,(LPWSTR)nm.c_str());

        const wchar_t* targets[] = {L"Application",L"Domain",L"IP",L"Port",L"All"};
        ListView_SetItemText(lv_rules_,(int)i,3,(LPWSTR)targets[(int)r.target]);

        std::wstring pat = utf8_to_wide(r.pattern);
        ListView_SetItemText(lv_rules_,(int)i,4,(LPWSTR)pat.c_str());

        const wchar_t* actions[] = {L"Use Proxy",L"Direct",L"Block",L"Use Chain"};
        ListView_SetItemText(lv_rules_,(int)i,5,(LPWSTR)actions[(int)r.action]);

        std::wstring pc = L"-";
        if (r.action == RuleAction::UseProxy && r.proxy_index >= 0)
            pc = L"Proxy #" + std::to_wstring(r.proxy_index + 1);
        else if (r.action == RuleAction::UseChain && r.chain_index >= 0)
            pc = L"Chain #" + std::to_wstring(r.chain_index + 1);
        ListView_SetItemText(lv_rules_,(int)i,6,(LPWSTR)pc.c_str());

        std::wstring pri = std::to_wstring(r.priority);
        ListView_SetItemText(lv_rules_,(int)i,7,(LPWSTR)pri.c_str());
    }
    SendMessage(lv_rules_, WM_SETREDRAW, TRUE, 0);
}

void MainWindow::refresh_connections_list() {
    uint16_t http_port = routing_active_ ? settings_.server_port : 0;
    uint16_t socks_port = routing_active_ ? (uint16_t)(settings_.server_port + 1) : (uint16_t)0;
    auto conns = ConnectionMonitor::get_system_connections(http_port, socks_port);

    SendMessage(lv_connections_, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(lv_connections_);
    for (size_t i = 0; i < conns.size(); ++i) {
        const auto& c = conns[i];
        LVITEMW item = {}; item.mask = LVIF_TEXT; item.iItem = (int)i;
        std::wstring app = utf8_to_wide(c.app_name);
        item.pszText = (LPWSTR)app.c_str();
        ListView_InsertItem(lv_connections_, &item);

        std::wstring pid = std::to_wstring(c.pid);
        ListView_SetItemText(lv_connections_,(int)i,1,(LPWSTR)pid.c_str());
        std::wstring laddr = utf8_to_wide(c.local_addr);
        ListView_SetItemText(lv_connections_,(int)i,2,(LPWSTR)laddr.c_str());
        std::wstring lport = std::to_wstring(c.local_port);
        ListView_SetItemText(lv_connections_,(int)i,3,(LPWSTR)lport.c_str());
        std::wstring raddr = utf8_to_wide(c.remote_addr);
        ListView_SetItemText(lv_connections_,(int)i,4,(LPWSTR)raddr.c_str());
        std::wstring rport = std::to_wstring(c.remote_port);
        ListView_SetItemText(lv_connections_,(int)i,5,(LPWSTR)rport.c_str());
        std::wstring state = utf8_to_wide(c.state);
        ListView_SetItemText(lv_connections_,(int)i,6,(LPWSTR)state.c_str());
        ListView_SetItemText(lv_connections_,(int)i,7,(LPWSTR)(c.is_proxied ? L"Yes" : L"No"));
    }
    SendMessage(lv_connections_, WM_SETREDRAW, TRUE, 0);
}

void MainWindow::refresh_logs_list() {
    auto logs = conn_monitor_.get_recent_logs(200);
    SendMessage(lv_logs_, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(lv_logs_);
    for (size_t i = 0; i < logs.size(); ++i) {
        const auto& l = logs[i];
        LVITEMW item = {}; item.mask = LVIF_TEXT; item.iItem = (int)i;
        wchar_t tb[32]; struct tm ti; localtime_s(&ti,&l.timestamp);
        wcsftime(tb,32,L"%m-%d %H:%M:%S",&ti);
        item.pszText = tb;
        ListView_InsertItem(lv_logs_, &item);

        std::wstring app = utf8_to_wide(l.app_name);
        ListView_SetItemText(lv_logs_,(int)i,1,(LPWSTR)app.c_str());
        std::wstring dest = utf8_to_wide(l.dest_host);
        ListView_SetItemText(lv_logs_,(int)i,2,(LPWSTR)dest.c_str());
        std::wstring port = std::to_wstring(l.dest_port);
        ListView_SetItemText(lv_logs_,(int)i,3,(LPWSTR)port.c_str());
        std::wstring proxy = utf8_to_wide(l.proxy_used);
        ListView_SetItemText(lv_logs_,(int)i,4,(LPWSTR)proxy.c_str());
        std::wstring meth = utf8_to_wide(l.method);
        ListView_SetItemText(lv_logs_,(int)i,5,(LPWSTR)meth.c_str());
        std::wstring st = std::to_wstring(l.http_status);
        ListView_SetItemText(lv_logs_,(int)i,6,(LPWSTR)st.c_str());
        std::wstring sent = format_bytes(l.bytes_sent);
        ListView_SetItemText(lv_logs_,(int)i,7,(LPWSTR)sent.c_str());
        std::wstring recv = format_bytes(l.bytes_received);
        ListView_SetItemText(lv_logs_,(int)i,8,(LPWSTR)recv.c_str());
        std::wstring rule = utf8_to_wide(l.rule_matched);
        ListView_SetItemText(lv_logs_,(int)i,9,(LPWSTR)rule.c_str());
        std::wstring err = utf8_to_wide(l.error);
        ListView_SetItemText(lv_logs_,(int)i,10,(LPWSTR)err.c_str());
    }
    SendMessage(lv_logs_, WM_SETREDRAW, TRUE, 0);
}

void MainWindow::update_listview_item(int index) {
    if (index < 0 || (size_t)index >= proxy_list_.size()) return;
    std::lock_guard<std::mutex> lock(proxy_list_.mutex());
    const Proxy& p = proxy_list_.at(index);
    ListView_SetItemText(lv_proxies_, index, 4, (LPWSTR)proxy_status_to_wstr(p.status));
    std::wstring lat = (p.latency_ms>=0)?std::to_wstring(p.latency_ms)+L" ms":L"-";
    ListView_SetItemText(lv_proxies_, index, 5, (LPWSTR)lat.c_str());
    ListView_SetItemText(lv_proxies_, index, 6, (LPWSTR)anonymity_to_wstr(p.anonymity));
}

void MainWindow::update_statusbar() {
    static wchar_t sb_text[3][128];

    swprintf(sb_text[0], 128, L"  Proxies: %zu  |  Rules: %zu",
             proxy_list_.size(), rules_engine_.rule_count());

    if (checker_.is_running())
        swprintf(sb_text[1], 128, L"  Checking: %d/%d", checker_.checked_count(), checker_.total_count());
    else {
        auto summary = conn_monitor_.get_summary();
        swprintf(sb_text[1], 128, L"  Connections: %llu active", (unsigned long long)summary.active_connections);
    }

    if (routing_active_)
        wcscpy(sb_text[2], L"  Routing Active");
    else
        wcscpy(sb_text[2], L"  Routing Off");

    for (int i = 0; i < 3; ++i)
        SendMessageW(statusbar_, SB_SETTEXTW, i, (LPARAM)sb_text[i]);
}

// ============================================================================
// Tray icon
// ============================================================================

void MainWindow::create_tray_icon() {
    nid_.cbSize = sizeof(nid_);
    nid_.hWnd = hwnd_;
    nid_.uID = 1;
    nid_.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid_.uCallbackMessage = WM_TRAY_ICON;
    nid_.hIcon = LoadIcon(hinstance_, MAKEINTRESOURCE(IDI_APP_ICON));
    if (!nid_.hIcon) nid_.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wcscpy(nid_.szTip, L"FlowProxy");
    Shell_NotifyIconW(NIM_ADD, &nid_);
}

void MainWindow::remove_tray_icon() {
    Shell_NotifyIconW(NIM_DELETE, &nid_);
}

void MainWindow::minimize_to_tray() {
    ShowWindow(hwnd_, SW_HIDE);
    in_tray_ = true;
    if (routing_active_)
        wcscpy(nid_.szTip, L"FlowProxy - Routing Active");
    else
        wcscpy(nid_.szTip, L"FlowProxy - Idle");
    Shell_NotifyIconW(NIM_MODIFY, &nid_);
}

void MainWindow::restore_from_tray() {
    ShowWindow(hwnd_, SW_SHOW);
    SetForegroundWindow(hwnd_);
    in_tray_ = false;
}

void MainWindow::on_tray_icon(LPARAM lParam) {
    switch (LOWORD(lParam)) {
    case WM_LBUTTONDBLCLK:
        restore_from_tray();
        break;
    case WM_RBUTTONUP: {
        POINT pt;
        GetCursorPos(&pt);
        HMENU popup = CreatePopupMenu();
        AppendMenuW(popup, MF_STRING, IDM_TRAY_RESTORE, L"&Restore");
        AppendMenuW(popup, MF_SEPARATOR, 0, nullptr);
        if (routing_active_)
            AppendMenuW(popup, MF_STRING, IDM_TOOLS_CLEAR_SYSTEM, L"&Disable Routing");
        else
            AppendMenuW(popup, MF_STRING, IDM_TOOLS_SET_SYSTEM, L"&Enable Routing");
        AppendMenuW(popup, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(popup, MF_STRING, IDM_TRAY_EXIT, L"E&xit");
        SetForegroundWindow(hwnd_);
        TrackPopupMenu(popup, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd_, nullptr);
        DestroyMenu(popup);
        break;
    }
    }
}

// ============================================================================
// Command dispatcher
// ============================================================================

void MainWindow::on_command(WPARAM wParam) {
    switch (LOWORD(wParam)) {
        case IDM_PROXY_ADD:         on_proxy_add(); break;
        case IDM_PROXY_EDIT:        on_proxy_edit(); break;
        case IDM_PROXY_DELETE:      on_proxy_delete(); break;
        case IDM_PROXY_DELETE_ALL:  on_proxy_delete_all(); break;
        case IDM_PROXY_DELETE_DEAD: on_proxy_delete_dead(); break;
        case IDM_CHECK_ALL:         on_check_all(); break;
        case IDM_CHECK_SELECTED:    on_check_selected(); break;
        case IDM_CHECK_STOP:        on_check_stop(); break;
        case IDM_FILE_IMPORT:       on_import(); break;
        case IDM_FILE_EXPORT:       on_export(); break;
        case IDM_FILE_SETTINGS:     on_settings(); break;
        case IDM_FILE_EXIT:         SendMessage(hwnd_, WM_CLOSE, 0, 0); break;
        case IDM_TOOLS_SET_SYSTEM:   on_enable_routing(); break;
        case IDM_TOOLS_CLEAR_SYSTEM: on_disable_routing(); break;
        case IDM_RULES_ADD:         on_rule_add(); break;
        case IDM_RULES_EDIT:        on_rule_edit(); break;
        case IDM_RULES_DELETE:      on_rule_delete(); break;
        case IDM_CHAIN_ADD:         on_chain_add(); break;
        case IDM_CHAIN_EDIT:        on_chain_edit(); break;
        case IDM_CHAIN_DELETE:      on_chain_delete(); break;
        case IDM_VIEW_STATS:        on_view_stats(); break;
        case IDM_VIEW_EXPORT_LOGS:  on_export_logs(); break;
        case IDM_VIEW_CLEAR_LOGS:   on_clear_logs(); break;
        case IDM_DNS_LOCAL:         on_dns_mode(DnsMode::Local); break;
        case IDM_DNS_REMOTE:        on_dns_mode(DnsMode::RemoteProxy); break;
        case IDM_DNS_CUSTOM:        on_dns_mode(DnsMode::CustomDNS); break;
        case IDM_DNS_FLUSH_CACHE:   on_dns_flush(); break;
        case IDM_HELP_ABOUT:        on_about(); break;
        case IDM_TRAY_RESTORE:      restore_from_tray(); break;
        case IDM_TRAY_EXIT:         SendMessage(hwnd_, WM_CLOSE, 0, 0); break;
    }
}

LRESULT MainWindow::on_notify(LPARAM lParam) {
    LPNMHDR nmhdr = (LPNMHDR)lParam;

    if (nmhdr->hwndFrom == tab_control_ && nmhdr->code == TCN_SELCHANGE) {
        on_tab_changed();
        return 0;
    }

    // Custom draw for ListViews
    if (nmhdr->code == NM_CUSTOMDRAW) {
        if (nmhdr->hwndFrom == lv_proxies_ || nmhdr->hwndFrom == lv_rules_ ||
            nmhdr->hwndFrom == lv_connections_ || nmhdr->hwndFrom == lv_logs_)
            return on_listview_custom_draw(lParam);
    }

    if (nmhdr->hwndFrom == lv_proxies_) {
        switch (nmhdr->code) {
        case NM_DBLCLK: on_proxy_edit(); break;
        case LVN_COLUMNCLICK: {
            auto nmlv = (LPNMLISTVIEW)lParam;
            SortColumn col = (SortColumn)(nmlv->iSubItem > 0 ? nmlv->iSubItem - 1 : 0);
            if (col == sort_column_) sort_ascending_ = !sort_ascending_;
            else { sort_column_ = col; sort_ascending_ = true; }
            proxy_list_.sort_by(sort_column_, sort_ascending_);
            refresh_proxy_list();
            break;
        }
        case LVN_KEYDOWN: {
            auto kd = (LPNMLVKEYDOWN)lParam;
            if (kd->wVKey == VK_DELETE) on_proxy_delete();
            else if (kd->wVKey == VK_INSERT) on_proxy_add();
            else if (kd->wVKey == VK_RETURN) on_proxy_edit();
            break;
        }
        }
    } else if (nmhdr->hwndFrom == lv_rules_ && nmhdr->code == NM_DBLCLK) {
        on_rule_edit();
    }
    return 0;
}

void MainWindow::on_context_menu(HWND hwnd, int x, int y) {
    if (hwnd == lv_proxies_) {
        HMENU popup = CreatePopupMenu();
        AppendMenuW(popup, MF_STRING, IDM_PROXY_ADD, L"Add Proxy...");
        AppendMenuW(popup, MF_STRING, IDM_PROXY_EDIT, L"Edit Proxy...");
        AppendMenuW(popup, MF_STRING, IDM_PROXY_DELETE, L"Delete Selected");
        AppendMenuW(popup, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(popup, MF_STRING, IDM_CHECK_SELECTED, L"Check Selected");
        AppendMenuW(popup, MF_STRING, IDM_CHECK_ALL, L"Check All");
        AppendMenuW(popup, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(popup, MF_STRING, IDM_PROXY_DELETE_DEAD, L"Delete Dead");
        TrackPopupMenu(popup, TPM_RIGHTBUTTON, x, y, 0, hwnd_, nullptr);
        DestroyMenu(popup);
    } else if (hwnd == lv_rules_) {
        HMENU popup = CreatePopupMenu();
        AppendMenuW(popup, MF_STRING, IDM_RULES_ADD, L"Add Rule...");
        AppendMenuW(popup, MF_STRING, IDM_RULES_EDIT, L"Edit Rule...");
        AppendMenuW(popup, MF_STRING, IDM_RULES_DELETE, L"Delete Rule");
        TrackPopupMenu(popup, TPM_RIGHTBUTTON, x, y, 0, hwnd_, nullptr);
        DestroyMenu(popup);
    }
}

void MainWindow::on_timer(WPARAM timer_id) {
    if (timer_id == IDT_STATS_REFRESH) {
        update_statusbar();
        if (current_tab_ == 2) refresh_connections_list();
        if (current_tab_ == 3) refresh_logs_list();
    } else if (timer_id == IDT_RATE_UPDATE) {
        conn_monitor_.update_rates();
    }
}

// ============================================================================
// Proxy commands
// ============================================================================

void MainWindow::on_proxy_add() {
    Proxy proxy;
    if (show_proxy_dialog(hwnd_, proxy, false, &checker_)) {
        proxy_list_.add(proxy);
        refresh_proxy_list();
        update_statusbar();
    }
}

void MainWindow::on_proxy_edit() {
    auto indices = get_selected_indices(lv_proxies_);
    if (indices.empty()) return;
    Proxy proxy;
    {
        std::lock_guard<std::mutex> lock(proxy_list_.mutex());
        if (indices[0] >= proxy_list_.proxies().size()) return;
        proxy = proxy_list_.proxies()[indices[0]];
    }
    if (show_proxy_dialog(hwnd_, proxy, true, &checker_)) {
        proxy_list_.update(indices[0], proxy);
        refresh_proxy_list();
    }
}

void MainWindow::on_proxy_delete() {
    auto indices = get_selected_indices(lv_proxies_);
    if (indices.empty()) return;
    wchar_t msg[128];
    swprintf(msg, 128, L"Delete %zu selected proxy(ies)?", indices.size());
    if (MessageBoxW(hwnd_, msg, L"Confirm", MB_YESNO|MB_ICONQUESTION) == IDYES) {
        proxy_list_.remove_indices(indices);
        refresh_proxy_list();
        update_statusbar();
    }
}

void MainWindow::on_proxy_delete_all() {
    if (proxy_list_.empty()) return;
    if (MessageBoxW(hwnd_, L"Delete all proxies?", L"Confirm", MB_YESNO|MB_ICONQUESTION) == IDYES) {
        proxy_list_.clear();
        refresh_proxy_list();
        update_statusbar();
    }
}

void MainWindow::on_proxy_delete_dead() {
    if (MessageBoxW(hwnd_, L"Delete all dead proxies?", L"Confirm", MB_YESNO|MB_ICONQUESTION) == IDYES) {
        proxy_list_.remove_dead();
        refresh_proxy_list();
        update_statusbar();
    }
}

void MainWindow::on_check_all() {
    if (proxy_list_.empty() || checker_.is_running()) return;
    checker_.check_all(proxy_list_, hwnd_);
    update_statusbar();
}

void MainWindow::on_check_selected() {
    auto indices = get_selected_indices(lv_proxies_);
    if (indices.empty() || checker_.is_running()) return;
    checker_.check_selected(proxy_list_, indices, hwnd_);
    update_statusbar();
}

void MainWindow::on_check_stop() { checker_.stop(); update_statusbar(); }

void MainWindow::on_import() {
    std::string path = open_file_dialog(false,
        "Proxy Files (*.txt;*.csv)\0*.txt;*.csv\0All Files\0*.*\0", "txt");
    if (path.empty()) return;
    auto proxies = ProxyImporter::import_from_file(path);
    for (auto& p : proxies) proxy_list_.add(p);
    refresh_proxy_list();
    update_statusbar();
    wchar_t msg[128];
    swprintf(msg, 128, L"Imported %zu proxies.", proxies.size());
    MessageBoxW(hwnd_, msg, L"Import", MB_ICONINFORMATION);
}

void MainWindow::on_export() {
    if (proxy_list_.empty()) { MessageBoxW(hwnd_, L"No proxies.", L"Export", MB_ICONWARNING); return; }
    std::string path = open_file_dialog(true, "Text (*.txt)\0*.txt\0CSV (*.csv)\0*.csv\0", "txt");
    if (path.empty()) return;
    std::vector<Proxy> proxies_copy;
    {
        std::lock_guard<std::mutex> lock(proxy_list_.mutex());
        proxies_copy = proxy_list_.proxies();
    }
    bool ok = (path.size()>4 && path.substr(path.size()-4)==".csv")
        ? ProxyImporter::export_to_csv(path, proxies_copy)
        : ProxyImporter::export_to_file(path, proxies_copy);
    MessageBoxW(hwnd_, ok ? L"Export successful." : L"Export failed.",
                ok ? L"Export" : L"Error", ok ? MB_ICONINFORMATION : MB_ICONERROR);
}

void MainWindow::on_settings() {
    if (show_settings_dialog(hwnd_, settings_)) {
        CheckerConfig cc;
        cc.thread_count = settings_.checker_threads;
        cc.timeout_ms = settings_.checker_timeout;
        cc.test_url = settings_.test_url;
        checker_.set_config(cc);
        Settings::save(settings_);
    }
}

// ============================================================================
// Routing (DLL injection based)
// ============================================================================

void MainWindow::on_enable_routing() {
    if (routing_active_) return;
    if (!interceptor_->start(settings_.server_port, settings_.rotation_mode)) {
        MessageBoxW(hwnd_, L"Failed to start. Port may be in use.", L"Error", MB_ICONERROR);
        return;
    }
    interceptor_->start_socks5(settings_.server_port + 1, settings_.rotation_mode);
    SystemProxy::set_system_proxy("127.0.0.1", settings_.server_port);
    routing_active_ = true;
    update_statusbar();
}

void MainWindow::on_disable_routing() {
    if (!routing_active_) return;
    SystemProxy::clear_system_proxy();
    interceptor_->stop();
    routing_active_ = false;
    update_statusbar();
}

// ============================================================================
// Rules
// ============================================================================

void MainWindow::on_rule_add() {
    ProxyRule rule;
    if (show_rule_dialog(hwnd_, rule, proxy_list_, chain_manager_, false)) {
        rules_engine_.add_rule(rule);
        refresh_rules_list();
    }
}

void MainWindow::on_rule_edit() {
    auto indices = get_selected_indices(lv_rules_);
    if (indices.empty()) return;
    ProxyRule rule = rules_engine_.rule_at(indices[0]);
    if (show_rule_dialog(hwnd_, rule, proxy_list_, chain_manager_, true)) {
        rules_engine_.update_rule(indices[0], rule);
        refresh_rules_list();
    }
}

void MainWindow::on_rule_delete() {
    auto indices = get_selected_indices(lv_rules_);
    if (indices.empty()) return;
    if (MessageBoxW(hwnd_, L"Delete selected rule?", L"Confirm", MB_YESNO|MB_ICONQUESTION) == IDYES) {
        rules_engine_.remove_rule(indices[0]);
        refresh_rules_list();
    }
}

// ============================================================================
// Chains
// ============================================================================

void MainWindow::on_chain_add() {
    ProxyChain chain;
    if (show_chain_dialog(hwnd_, chain, proxy_list_, false)) {
        chain_manager_.add_chain(chain);
    }
}

void MainWindow::on_chain_edit() {
    if (chain_manager_.chain_count() == 0) {
        MessageBoxW(hwnd_, L"No chains to edit.", L"Chains", MB_ICONINFORMATION);
        return;
    }
    ProxyChain chain = chain_manager_.chain_at(0);
    if (show_chain_dialog(hwnd_, chain, proxy_list_, true)) {
        chain_manager_.update_chain(0, chain);
    }
}

void MainWindow::on_chain_delete() {
    if (chain_manager_.chain_count() == 0) {
        MessageBoxW(hwnd_, L"No chains to delete.", L"Chains", MB_ICONINFORMATION);
        return;
    }
    if (MessageBoxW(hwnd_, L"Delete first chain?", L"Confirm", MB_YESNO|MB_ICONQUESTION) == IDYES) {
        chain_manager_.remove_chain(0);
    }
}

// ============================================================================
// View / DNS
// ============================================================================

void MainWindow::on_view_stats() {
    auto s = conn_monitor_.get_summary();
    wchar_t msg[512];
    swprintf(msg, 512,
        L"Traffic Statistics\n\n"
        L"Total connections: %llu\n"
        L"Active connections: %llu\n"
        L"Failed connections: %llu\n\n"
        L"Data sent: %llu bytes\n"
        L"Data received: %llu bytes\n\n"
        L"Send rate: %.1f KB/s\n"
        L"Receive rate: %.1f KB/s\n\n"
        L"DNS queries: %llu (cache hits: %llu)\n"
        L"DNS cache entries: %zu",
        (unsigned long long)s.total_connections,
        (unsigned long long)s.active_connections,
        (unsigned long long)s.failed_connections,
        (unsigned long long)s.total_bytes_sent,
        (unsigned long long)s.total_bytes_received,
        s.current_send_rate / 1024.0,
        s.current_recv_rate / 1024.0,
        (unsigned long long)s.dns_queries,
        (unsigned long long)s.dns_cache_hits,
        dns_resolver_.cache_size());
    MessageBoxW(hwnd_, msg, L"Traffic Statistics", MB_ICONINFORMATION);
}

void MainWindow::on_export_logs() {
    std::string path = open_file_dialog(true, "CSV (*.csv)\0*.csv\0", "csv");
    if (path.empty()) return;
    if (conn_monitor_.export_logs(path))
        MessageBoxW(hwnd_, L"Logs exported.", L"Export", MB_ICONINFORMATION);
    else
        MessageBoxW(hwnd_, L"Export failed.", L"Error", MB_ICONERROR);
}

void MainWindow::on_clear_logs() {
    conn_monitor_.clear_logs();
    refresh_logs_list();
}

void MainWindow::on_dns_mode(DnsMode mode) {
    dns_resolver_.set_mode(mode);
    const wchar_t* names[] = {L"Local DNS", L"Remote DNS (via proxy)", L"Custom DNS", L"DNS-over-HTTPS"};
    wchar_t msg[128];
    swprintf(msg, 128, L"DNS mode set to: %s\n%s",
             names[(int)mode],
             mode == DnsMode::RemoteProxy ? L"DNS queries now go through proxy. No DNS leaks!" :
             mode == DnsMode::Local ? L"Warning: DNS queries may leak to local network." : L"");
    MessageBoxW(hwnd_, msg, L"DNS Settings", MB_ICONINFORMATION);
}

void MainWindow::on_dns_flush() {
    dns_resolver_.flush_cache();
    MessageBoxW(hwnd_, L"DNS cache flushed.", L"DNS", MB_ICONINFORMATION);
}

void MainWindow::on_about() {
    show_about_dialog(hwnd_);
}

// ============================================================================
// Theme / Custom Draw
// ============================================================================

void MainWindow::apply_dark_theme() {
    SetWindowTheme(tab_control_, L"Explorer", nullptr);
    SetWindowTheme(statusbar_, L"Explorer", nullptr);
}

LRESULT MainWindow::on_listview_custom_draw(LPARAM lParam) {
    auto* cd = (LPNMLVCUSTOMDRAW)lParam;

    switch (cd->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;

    case CDDS_ITEMPREPAINT: {
        int item = (int)cd->nmcd.dwItemSpec;
        bool selected = (cd->nmcd.uItemState & CDIS_SELECTED) != 0;
        bool hot = (cd->nmcd.uItemState & CDIS_HOT) != 0;

        if (selected) {
            cd->clrTextBk = Theme::BG_SELECTED;
            cd->clrText = Theme::TEXT_PRIMARY;
        } else if (hot) {
            cd->clrTextBk = Theme::BG_HOVER;
            cd->clrText = Theme::TEXT_PRIMARY;
        } else {
            cd->clrTextBk = (item % 2 == 0) ? Theme::BG_WHITE : Theme::BG_ALT_ROW;
            cd->clrText = Theme::TEXT_PRIMARY;
        }

        if (cd->nmcd.hdr.hwndFrom == lv_proxies_) {
            return CDRF_NOTIFYSUBITEMDRAW;
        }
        return CDRF_NEWFONT;
    }

    case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
        int item = (int)cd->nmcd.dwItemSpec;
        int sub = cd->iSubItem;
        bool selected = (cd->nmcd.uItemState & CDIS_SELECTED) != 0;

        if (!selected && cd->nmcd.hdr.hwndFrom == lv_proxies_) {
            if (sub == 4) {
                wchar_t text[32] = {};
                ListView_GetItemText(lv_proxies_, item, 4, text, 32);
                if (wcscmp(text, L"Alive") == 0)
                    cd->clrText = Theme::STATUS_ALIVE;
                else if (wcscmp(text, L"Dead") == 0)
                    cd->clrText = Theme::STATUS_DEAD;
                else if (wcscmp(text, L"Checking") == 0)
                    cd->clrText = Theme::STATUS_CHECK;
                else
                    cd->clrText = Theme::TEXT_DIM;
            }
            else if (sub == 5) {
                wchar_t text[32] = {};
                ListView_GetItemText(lv_proxies_, item, 5, text, 32);
                if (wcscmp(text, L"-") == 0)
                    cd->clrText = Theme::TEXT_DIM;
            }
            else if (sub == 0) {
                cd->clrText = Theme::TEXT_SECONDARY;
            }
        }
        return CDRF_NEWFONT;
    }
    }

    return CDRF_DODEFAULT;
}

LRESULT MainWindow::on_toolbar_custom_draw(LPARAM lParam) {
    auto* cd = (LPNMTBCUSTOMDRAW)lParam;

    switch (cd->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW | CDRF_NOTIFYPOSTPAINT;

    case CDDS_PREERASE: {
        RECT rc;
        GetClientRect(toolbar_, &rc);
        Theme::fill_rect(cd->nmcd.hdc, rc, Theme::BG_TOOLBAR);
        return CDRF_SKIPDEFAULT;
    }

    case CDDS_ITEMPREPAINT: {
        HDC hdc = cd->nmcd.hdc;
        RECT rc = cd->nmcd.rc;
        bool hot = (cd->nmcd.uItemState & CDIS_HOT) != 0;
        bool pressed = (cd->nmcd.uItemState & CDIS_SELECTED) != 0;

        COLORREF bg = Theme::BG_TOOLBAR;
        if (pressed) bg = Theme::ACCENT_LIGHT;
        else if (hot) bg = Theme::BG_HOVER;
        Theme::fill_rect(hdc, rc, bg);

        cd->clrText = pressed ? Theme::ACCENT : (hot ? Theme::ACCENT_HOVER : Theme::TEXT_PRIMARY);
        cd->clrBtnFace = bg;

        SelectObject(hdc, Theme::hfont_ui);
        return TBCDRF_USECDCOLORS | TBCDRF_NOBACKGROUND;
    }

    case CDDS_POSTPAINT: {
        RECT rc;
        GetClientRect(toolbar_, &rc);
        RECT line = { rc.left, rc.bottom - 1, rc.right, rc.bottom };
        Theme::fill_rect(cd->nmcd.hdc, line, Theme::BORDER);
        return CDRF_SKIPDEFAULT;
    }
    }

    return CDRF_DODEFAULT;
}

void MainWindow::draw_tab_item(LPDRAWITEMSTRUCT dis) {
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    int index = dis->itemID;
    bool active = (index == current_tab_);

    // Background
    COLORREF bg = active ? Theme::TAB_ACTIVE_BG : Theme::TAB_INACTIVE_BG;
    Theme::fill_rect(hdc, rc, bg);

    // Active tab: blue accent underline
    if (active) {
        RECT accent = { rc.left + 8, rc.bottom - 3, rc.right - 8, rc.bottom };
        Theme::fill_rect(hdc, accent, Theme::ACCENT);
    }

    // Subtle border between tabs
    RECT border = { rc.right - 1, rc.top + 6, rc.right, rc.bottom - 6 };
    Theme::fill_rect(hdc, border, Theme::BORDER_LIGHT);

    // Tab text
    wchar_t text[64] = {};
    TCITEMW ti = {};
    ti.mask = TCIF_TEXT;
    ti.pszText = text;
    ti.cchTextMax = 64;
    TabCtrl_GetItem(tab_control_, index, &ti);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, active ? Theme::ACCENT : Theme::TEXT_SECONDARY);
    SelectObject(hdc, active ? Theme::hfont_ui_bold : Theme::hfont_ui);
    DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void MainWindow::draw_statusbar_part(LPDRAWITEMSTRUCT dis) {
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    int part = dis->itemID;
    const wchar_t* text = (const wchar_t*)dis->itemData;

    COLORREF bg = Theme::STATUSBAR_BG;
    COLORREF fg = Theme::TEXT_WHITE;
    if (part == 4 && routing_active_) {
        bg = Theme::STATUSBAR_ACTIVE;
    }

    Theme::fill_rect(hdc, rc, bg);

    // Subtle separator
    if (part < 4) {
        RECT sep = { rc.right - 1, rc.top + 4, rc.right, rc.bottom - 4 };
        COLORREF sep_color = RGB(
            GetRValue(bg) + 30 > 255 ? 255 : GetRValue(bg) + 30,
            GetGValue(bg) + 30 > 255 ? 255 : GetGValue(bg) + 30,
            GetBValue(bg) + 30 > 255 ? 255 : GetBValue(bg) + 30
        );
        Theme::fill_rect(hdc, sep, sep_color);
    }

    if (text) {
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, fg);
        SelectObject(hdc, Theme::hfont_ui);
        DrawTextW(hdc, text, -1, &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }
}

// ============================================================================
// Helpers
// ============================================================================

std::vector<size_t> MainWindow::get_selected_indices(HWND lv) {
    std::vector<size_t> indices;
    int index = -1;
    while ((index = ListView_GetNextItem(lv, index, LVNI_SELECTED)) != -1)
        indices.push_back((size_t)index);
    return indices;
}

std::string MainWindow::open_file_dialog(bool save, const char* filter, const char* default_ext) {
    char filename[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = default_ext;
    if (save) {
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
        if (!GetSaveFileNameA(&ofn)) return "";
    } else {
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        if (!GetOpenFileNameA(&ofn)) return "";
    }
    return std::string(filename);
}
