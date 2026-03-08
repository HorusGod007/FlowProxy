#include "gui/dialogs.h"
#include "resources/resource.h"
#include <string>
#include <thread>
#include <commctrl.h>

// ============================================================================
// In-memory dialog template helper
// ============================================================================

struct DlgBuilder {
    WORD buf[4096];
    WORD* ptr;
    DLGTEMPLATE* dlg;
    int item_count = 0;

    DlgBuilder(short w, short h, const wchar_t* title) {
        memset(buf, 0, sizeof(buf));
        dlg = (DLGTEMPLATE*)buf;
        dlg->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_SETFONT;
        dlg->cx = w; dlg->cy = h;
        ptr = (WORD*)(dlg + 1);
        *ptr++ = 0; *ptr++ = 0; // menu, class
        while (*title) *ptr++ = *title++;
        *ptr++ = 0;
        *ptr++ = 9; // font size
        const wchar_t* font = L"Segoe UI";
        while (*font) *ptr++ = *font++;
        *ptr++ = 0;
    }

    void add(DWORD style, short x, short y, short cx, short cy, WORD id,
             const wchar_t* cls, const wchar_t* text) {
        ptr = (WORD*)(((ULONG_PTR)ptr + 3) & ~3);
        DLGITEMTEMPLATE* item = (DLGITEMTEMPLATE*)ptr;
        item->style = style | WS_CHILD | WS_VISIBLE;
        item->x = x; item->y = y; item->cx = cx; item->cy = cy; item->id = id;
        ptr = (WORD*)(item + 1);
        while (*cls) *ptr++ = *cls++;
        *ptr++ = 0;
        while (*text) *ptr++ = *text++;
        *ptr++ = 0;
        *ptr++ = 0;
        ++item_count;
    }

    DLGTEMPLATE* finish() { dlg->cdit = (WORD)item_count; return dlg; }
};

// ============================================================================
// Tooltip helper
// ============================================================================

static HWND create_tooltip(HWND parent) {
    HWND tip = CreateWindowExW(0, TOOLTIPS_CLASSW, nullptr,
        WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        parent, nullptr, GetModuleHandle(0), nullptr);
    SendMessage(tip, TTM_SETMAXTIPWIDTH, 0, 300);
    return tip;
}

static void add_tooltip(HWND tip_wnd, HWND parent, HWND control, const wchar_t* text) {
    TOOLINFOW ti = {};
    ti.cbSize = sizeof(ti);
    ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    ti.hwnd = parent;
    ti.uId = (UINT_PTR)control;
    ti.lpszText = (LPWSTR)text;
    SendMessageW(tip_wnd, TTM_ADDTOOLW, 0, (LPARAM)&ti);
}

// ============================================================================
// Proxy Dialog
// ============================================================================

struct ProxyDialogData { Proxy* proxy; bool edit_mode; bool confirmed; ProxyChecker* checker; };

static INT_PTR CALLBACK proxy_dlg_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    auto* d = (ProxyDialogData*)GetWindowLongPtr(h, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG: {
        d = (ProxyDialogData*)lp;
        SetWindowLongPtr(h, GWLP_USERDATA, (LONG_PTR)d);
        SetDlgItemTextW(h, IDC_EDIT_HOST, utf8_to_wide(d->proxy->host).c_str());
        SetDlgItemTextW(h, IDC_EDIT_PORT, std::to_wstring(d->proxy->port).c_str());
        SetDlgItemTextW(h, IDC_EDIT_USER, utf8_to_wide(d->proxy->username).c_str());
        SetDlgItemTextW(h, IDC_EDIT_PASS, utf8_to_wide(d->proxy->password).c_str());
        HWND cb = GetDlgItem(h, IDC_COMBO_TYPE);
        const wchar_t* types[] = {L"HTTP",L"HTTPS",L"SOCKS4",L"SOCKS5"};
        for (auto t : types) SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)t);
        SendMessageW(cb, CB_SETCURSEL, proxy_type_to_index(d->proxy->type), 0);

        // Add placeholder text (EM_SETCUEBANNER)
        SendDlgItemMessageW(h, IDC_EDIT_HOST, EM_SETCUEBANNER, TRUE, (LPARAM)L"e.g. 192.168.1.1 or proxy.example.com");
        SendDlgItemMessageW(h, IDC_EDIT_PORT, EM_SETCUEBANNER, TRUE, (LPARAM)L"e.g. 8080");
        SendDlgItemMessageW(h, IDC_EDIT_USER, EM_SETCUEBANNER, TRUE, (LPARAM)L"(optional)");
        SendDlgItemMessageW(h, IDC_EDIT_PASS, EM_SETCUEBANNER, TRUE, (LPARAM)L"(optional)");

        // Tooltips
        HWND tip = create_tooltip(h);
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_HOST), L"IP address or hostname of the proxy server");
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_PORT), L"Port number (1-65535)");
        add_tooltip(tip, h, cb, L"HTTP: web proxy\nHTTPS: encrypted web proxy\nSOCKS4: basic SOCKS\nSOCKS5: SOCKS with auth + UDP");
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_USER), L"Username for proxy authentication (leave empty if none)");
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_PASS), L"Password for proxy authentication (leave empty if none)");

        RECT rc, prc; GetWindowRect(h,&rc); GetWindowRect(GetParent(h),&prc);
        SetWindowPos(h,0,prc.left+(prc.right-prc.left-(rc.right-rc.left))/2,
                     prc.top+(prc.bottom-prc.top-(rc.bottom-rc.top))/2,0,0,SWP_NOSIZE|SWP_NOZORDER);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_BTN_CHECK_PROXY && d->checker) {
            wchar_t b[256];
            GetDlgItemTextW(h,IDC_EDIT_HOST,b,256);
            std::string host = wide_to_utf8(b);
            GetDlgItemTextW(h,IDC_EDIT_PORT,b,256);
            uint16_t port = 0;
            try { port = (uint16_t)std::stoi(wide_to_utf8(b)); } catch(...) {}
            if (host.empty() || port == 0) {
                SetDlgItemTextW(h, IDC_STATIC_CHECK_RESULT, L"Enter host and port first.");
                return TRUE;
            }
            Proxy test;
            test.host = host;
            test.port = port;
            test.type = proxy_type_from_index((int)SendDlgItemMessageW(h,IDC_COMBO_TYPE,CB_GETCURSEL,0,0));
            GetDlgItemTextW(h,IDC_EDIT_USER,b,256); test.username = wide_to_utf8(b);
            GetDlgItemTextW(h,IDC_EDIT_PASS,b,256); test.password = wide_to_utf8(b);
            SetDlgItemTextW(h, IDC_STATIC_CHECK_RESULT, L"Checking...");
            EnableWindow(GetDlgItem(h, IDC_BTN_CHECK_PROXY), FALSE);
            // Run check in a thread so the dialog stays responsive
            std::thread([h, test, d]() mutable {
                bool alive = d->checker->check_single_proxy(test);
                wchar_t result[128];
                if (alive)
                    swprintf(result, 128, L"Alive  (%d ms)", test.latency_ms);
                else
                    swprintf(result, 128, L"Dead  (connection failed)");
                PostMessage(h, WM_APP + 1, 0, 0); // re-enable button
                SetDlgItemTextW(h, IDC_STATIC_CHECK_RESULT, result);
            }).detach();
            return TRUE;
        }
        if (LOWORD(wp) == IDOK) {
            wchar_t b[256];
            GetDlgItemTextW(h,IDC_EDIT_HOST,b,256); d->proxy->host = wide_to_utf8(b);
            GetDlgItemTextW(h,IDC_EDIT_PORT,b,256);
            try { d->proxy->port = (uint16_t)std::stoi(wide_to_utf8(b)); } catch(...) { d->proxy->port=0; }
            d->proxy->type = proxy_type_from_index((int)SendDlgItemMessageW(h,IDC_COMBO_TYPE,CB_GETCURSEL,0,0));
            GetDlgItemTextW(h,IDC_EDIT_USER,b,256); d->proxy->username = wide_to_utf8(b);
            GetDlgItemTextW(h,IDC_EDIT_PASS,b,256); d->proxy->password = wide_to_utf8(b);
            if (d->proxy->host.empty()||d->proxy->port==0) {
                MessageBoxW(h,L"Enter valid host and port.",L"Error",MB_ICONWARNING); return TRUE;
            }
            d->confirmed = true; EndDialog(h, IDOK); return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(h, IDCANCEL); return TRUE; }
        break;
    case WM_APP + 1:
        EnableWindow(GetDlgItem(h, IDC_BTN_CHECK_PROXY), TRUE);
        return TRUE;
    }
    return FALSE;
}

bool show_proxy_dialog(HWND parent, Proxy& proxy, bool edit_mode,
                       ProxyChecker* checker) {
    ProxyDialogData data{&proxy, edit_mode, false, checker};
    DlgBuilder b(240, 205, edit_mode ? L"Edit Proxy" : L"Add Proxy");

    b.add(SS_LEFT,12,12,45,9,0xFFFF,L"Static",L"Host:");
    b.add(WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,65,10,165,14,IDC_EDIT_HOST,L"Edit",L"");

    b.add(SS_LEFT,12,32,45,9,0xFFFF,L"Static",L"Port:");
    b.add(WS_BORDER|WS_TABSTOP|ES_NUMBER,65,30,65,14,IDC_EDIT_PORT,L"Edit",L"");

    b.add(SS_LEFT,12,52,45,9,0xFFFF,L"Static",L"Type:");
    b.add(CBS_DROPDOWNLIST|WS_TABSTOP,65,50,90,100,IDC_COMBO_TYPE,L"ComboBox",L"");

    b.add(SS_LEFT,12,74,50,9,0xFFFF,L"Static",L"Username:");
    b.add(WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,65,72,165,14,IDC_EDIT_USER,L"Edit",L"");

    b.add(SS_LEFT,12,94,50,9,0xFFFF,L"Static",L"Password:");
    b.add(WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL|ES_PASSWORD,65,92,165,14,IDC_EDIT_PASS,L"Edit",L"");

    b.add(SS_LEFT,12,114,220,9,0xFFFF,L"Static",L"Username and password are optional for most proxies.");

    // Check button and result
    b.add(BS_PUSHBUTTON|WS_TABSTOP,12,130,55,16,IDC_BTN_CHECK_PROXY,L"Button",L"Check");
    b.add(SS_LEFT,72,133,160,9,IDC_STATIC_CHECK_RESULT,L"Static",L"");

    b.add(BS_DEFPUSHBUTTON|WS_TABSTOP,75,158,55,16,IDOK,L"Button",L"Save");
    b.add(BS_PUSHBUTTON|WS_TABSTOP,140,158,55,16,IDCANCEL,L"Button",L"Cancel");
    DialogBoxIndirectParamW(GetModuleHandle(0), b.finish(), parent, proxy_dlg_proc, (LPARAM)&data);
    return data.confirmed;
}

// ============================================================================
// Settings Dialog
// ============================================================================

struct SettingsData { AppSettings* s; bool confirmed; };

static INT_PTR CALLBACK settings_dlg_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    auto* d = (SettingsData*)GetWindowLongPtr(h, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG: {
        d = (SettingsData*)lp;
        SetWindowLongPtr(h, GWLP_USERDATA, (LONG_PTR)d);
        SetDlgItemTextW(h,IDC_EDIT_THREADS,std::to_wstring(d->s->checker_threads).c_str());
        SetDlgItemTextW(h,IDC_EDIT_TIMEOUT,std::to_wstring(d->s->checker_timeout).c_str());
        SetDlgItemTextW(h,IDC_EDIT_TEST_URL,utf8_to_wide(d->s->test_url).c_str());
        SetDlgItemTextW(h,IDC_EDIT_SERVER_PORT,std::to_wstring(d->s->server_port).c_str());
        HWND cb = GetDlgItem(h,IDC_COMBO_ROTATION);
        SendMessageW(cb,CB_ADDSTRING,0,(LPARAM)L"Round Robin");
        SendMessageW(cb,CB_ADDSTRING,0,(LPARAM)L"Random");
        SendMessageW(cb,CB_ADDSTRING,0,(LPARAM)L"Least Latency");
        SendMessageW(cb,CB_SETCURSEL,(int)d->s->rotation_mode,0);

        HWND tip = create_tooltip(h);
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_THREADS), L"Number of parallel threads for checking proxies (1-100)");
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_TIMEOUT), L"Connection timeout in milliseconds when checking proxies");
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_TEST_URL), L"URL used to test if a proxy is working");
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_SERVER_PORT), L"Local port the interceptor listens on");
        add_tooltip(tip, h, cb, L"Round Robin: cycle through proxies in order\nRandom: pick random proxy\nLeast Latency: prefer fastest proxy");

        RECT rc,prc; GetWindowRect(h,&rc); GetWindowRect(GetParent(h),&prc);
        SetWindowPos(h,0,prc.left+(prc.right-prc.left-(rc.right-rc.left))/2,
                     prc.top+(prc.bottom-prc.top-(rc.bottom-rc.top))/2,0,0,SWP_NOSIZE|SWP_NOZORDER);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp)==IDOK) {
            wchar_t b[512];
            GetDlgItemTextW(h,IDC_EDIT_THREADS,b,512);
            try{d->s->checker_threads=std::stoi(wide_to_utf8(b));}catch(...){}
            GetDlgItemTextW(h,IDC_EDIT_TIMEOUT,b,512);
            try{d->s->checker_timeout=std::stoi(wide_to_utf8(b));}catch(...){}
            GetDlgItemTextW(h,IDC_EDIT_TEST_URL,b,512); d->s->test_url=wide_to_utf8(b);
            GetDlgItemTextW(h,IDC_EDIT_SERVER_PORT,b,512);
            try{d->s->server_port=(uint16_t)std::stoi(wide_to_utf8(b));}catch(...){}
            d->s->rotation_mode=(RotationMode)SendDlgItemMessageW(h,IDC_COMBO_ROTATION,CB_GETCURSEL,0,0);
            if(d->s->checker_threads<1)d->s->checker_threads=1;
            if(d->s->checker_threads>100)d->s->checker_threads=100;
            d->confirmed=true; EndDialog(h,IDOK); return TRUE;
        }
        if (LOWORD(wp)==IDCANCEL) { EndDialog(h,IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

bool show_settings_dialog(HWND parent, AppSettings& settings) {
    SettingsData data{&settings, false};
    DlgBuilder b(270, 185, L"Settings");

    b.add(SS_LEFT,12,12,75,9,0xFFFF,L"Static",L"Checker Threads:");
    b.add(WS_BORDER|WS_TABSTOP|ES_NUMBER,95,10,45,14,IDC_EDIT_THREADS,L"Edit",L"");

    b.add(SS_LEFT,12,32,75,9,0xFFFF,L"Static",L"Timeout (ms):");
    b.add(WS_BORDER|WS_TABSTOP|ES_NUMBER,95,30,65,14,IDC_EDIT_TIMEOUT,L"Edit",L"");

    b.add(SS_LEFT,12,52,75,9,0xFFFF,L"Static",L"Test URL:");
    b.add(WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,95,50,165,14,IDC_EDIT_TEST_URL,L"Edit",L"");

    b.add(SS_LEFT,12,74,75,9,0xFFFF,L"Static",L"Server Port:");
    b.add(WS_BORDER|WS_TABSTOP|ES_NUMBER,95,72,65,14,IDC_EDIT_SERVER_PORT,L"Edit",L"");

    b.add(SS_LEFT,12,94,75,9,0xFFFF,L"Static",L"Rotation:");
    b.add(CBS_DROPDOWNLIST|WS_TABSTOP,95,92,110,100,IDC_COMBO_ROTATION,L"ComboBox",L"");

    b.add(SS_LEFT,12,115,250,9,0xFFFF,L"Static",L"Changes take effect after restart.");

    b.add(BS_DEFPUSHBUTTON|WS_TABSTOP,90,135,55,16,IDOK,L"Button",L"Save");
    b.add(BS_PUSHBUTTON|WS_TABSTOP,155,135,55,16,IDCANCEL,L"Button",L"Cancel");
    DialogBoxIndirectParamW(GetModuleHandle(0), b.finish(), parent, settings_dlg_proc, (LPARAM)&data);
    return data.confirmed;
}

// ============================================================================
// Rule Dialog
// ============================================================================

struct RuleData {
    ProxyRule* rule;
    const ProxyList* proxies;
    const ProxyChainManager* chains;
    bool edit_mode;
    bool confirmed;
};

// Convert stored semicolons to newlines for multiline display
static std::wstring semis_to_lines(const std::string& s) {
    std::wstring wide = utf8_to_wide(s);
    std::wstring result, token;
    for (auto c : wide) {
        if (c == L';') {
            while (!token.empty() && token[0] == L' ') token.erase(0, 1);
            while (!token.empty() && token.back() == L' ') token.pop_back();
            if (!token.empty()) {
                if (!result.empty()) result += L"\r\n";
                result += token;
            }
            token.clear();
        } else {
            token += c;
        }
    }
    while (!token.empty() && token[0] == L' ') token.erase(0, 1);
    while (!token.empty() && token.back() == L' ') token.pop_back();
    if (!token.empty()) {
        if (!result.empty()) result += L"\r\n";
        result += token;
    }
    return result;
}

// Convert newlines/semicolons back to semicolons for storage
static std::string lines_to_semis(const wchar_t* text) {
    std::wstring wide(text);
    std::string result;
    std::wstring token;
    for (auto c : wide) {
        if (c == L'\r') continue;
        if (c == L'\n' || c == L';') {
            while (!token.empty() && token[0] == L' ') token.erase(0, 1);
            while (!token.empty() && token.back() == L' ') token.pop_back();
            if (!token.empty()) {
                if (!result.empty()) result += "; ";
                result += wide_to_utf8(token);
            }
            token.clear();
        } else {
            token += c;
        }
    }
    while (!token.empty() && token[0] == L' ') token.erase(0, 1);
    while (!token.empty() && token.back() == L' ') token.pop_back();
    if (!token.empty()) {
        if (!result.empty()) result += "; ";
        result += wide_to_utf8(token);
    }
    return result;
}

static INT_PTR CALLBACK rule_dlg_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    auto* d = (RuleData*)GetWindowLongPtr(h, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG: {
        d = (RuleData*)lp;
        SetWindowLongPtr(h, GWLP_USERDATA, (LONG_PTR)d);

        SetDlgItemTextW(h, IDC_EDIT_RULE_NAME, utf8_to_wide(d->rule->name).c_str());
        SetDlgItemTextW(h, IDC_EDIT_RULE_APPS, semis_to_lines(d->rule->apps).c_str());
        SetDlgItemTextW(h, IDC_EDIT_RULE_HOSTS, semis_to_lines(d->rule->hosts).c_str());
        SetDlgItemTextW(h, IDC_EDIT_RULE_PORTS, utf8_to_wide(d->rule->ports).c_str());

        HWND action_cb = GetDlgItem(h, IDC_COMBO_RULE_ACTION);
        const wchar_t* actions[] = {L"Use Proxy",L"Direct (bypass proxy)",L"Block",L"Use Chain"};
        for (auto a : actions) SendMessageW(action_cb, CB_ADDSTRING, 0, (LPARAM)a);
        SendMessageW(action_cb, CB_SETCURSEL, (int)d->rule->action, 0);

        HWND proxy_cb = GetDlgItem(h, IDC_COMBO_RULE_PROXY);
        SendMessageW(proxy_cb, CB_ADDSTRING, 0, (LPARAM)L"(Auto-rotate)");
        for (size_t i = 0; i < d->proxies->size(); ++i) {
            std::wstring label = std::to_wstring(i+1) + L": " +
                utf8_to_wide(d->proxies->proxies()[i].address());
            SendMessageW(proxy_cb, CB_ADDSTRING, 0, (LPARAM)label.c_str());
        }
        SendMessageW(proxy_cb, CB_SETCURSEL, d->rule->proxy_index + 1, 0);

        HWND chain_cb = GetDlgItem(h, IDC_COMBO_RULE_CHAIN);
        SendMessageW(chain_cb, CB_ADDSTRING, 0, (LPARAM)L"(None)");
        for (size_t i = 0; i < d->chains->chain_count(); ++i) {
            std::wstring label = utf8_to_wide(d->chains->chain_at(i).name);
            SendMessageW(chain_cb, CB_ADDSTRING, 0, (LPARAM)label.c_str());
        }
        SendMessageW(chain_cb, CB_SETCURSEL, d->rule->chain_index + 1, 0);

        // Placeholder text
        SendDlgItemMessageW(h, IDC_EDIT_RULE_NAME, EM_SETCUEBANNER, TRUE, (LPARAM)L"e.g. Stream sites");
        SendDlgItemMessageW(h, IDC_EDIT_RULE_PORTS, EM_SETCUEBANNER, TRUE, (LPARAM)L"e.g. 80, 443 or 1-1024");

        // Tooltips
        HWND tip = create_tooltip(h);
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_RULE_NAME),
            L"A friendly name for this rule.");
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_RULE_APPS),
            L"One exe name per line. Wildcards: * and ?\n"
            L"Leave empty to match all applications.\n\n"
            L"Examples:\n"
            L"  chrome.exe\n"
            L"  firefox.exe\n"
            L"  *torrent*");
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_RULE_HOSTS),
            L"One domain or IP per line. Wildcards: * and ?\n"
            L"Domains auto-match subdomains.\n"
            L"Leave empty to match all hosts.\n\n"
            L"Examples:\n"
            L"  netflix.com\n"
            L"  *.google.com\n"
            L"  192.168.0.0/16");
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_RULE_PORTS),
            L"Comma-separated ports or ranges.\n"
            L"Leave empty to match all ports.\n\n"
            L"Examples: 80, 443   or   1-1024");
        add_tooltip(tip, h, action_cb,
            L"Use Proxy: route through proxy\n"
            L"Direct: connect without proxy\n"
            L"Block: drop the connection\n"
            L"Use Chain: multi-hop proxy chain");
        add_tooltip(tip, h, proxy_cb,
            L"Pick a specific proxy or auto-rotate.");
        add_tooltip(tip, h, chain_cb,
            L"Only used when Action is 'Use Chain'.");

        RECT rc,prc; GetWindowRect(h,&rc); GetWindowRect(GetParent(h),&prc);
        SetWindowPos(h,0,prc.left+(prc.right-prc.left-(rc.right-rc.left))/2,
                     prc.top+(prc.bottom-prc.top-(rc.bottom-rc.top))/2,0,0,SWP_NOSIZE|SWP_NOZORDER);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp)==IDOK) {
            wchar_t b[256];
            GetDlgItemTextW(h,IDC_EDIT_RULE_NAME,b,256); d->rule->name = wide_to_utf8(b);
            // Read multiline fields, convert newlines to semicolons
            wchar_t buf[2048] = {};
            GetDlgItemTextW(h,IDC_EDIT_RULE_APPS,buf,2048); d->rule->apps = lines_to_semis(buf);
            GetDlgItemTextW(h,IDC_EDIT_RULE_HOSTS,buf,2048); d->rule->hosts = lines_to_semis(buf);
            GetDlgItemTextW(h,IDC_EDIT_RULE_PORTS,b,256); d->rule->ports = wide_to_utf8(b);
            // Trim ports
            while (!d->rule->ports.empty() && d->rule->ports[0] == ' ') d->rule->ports.erase(0,1);
            while (!d->rule->ports.empty() && d->rule->ports.back() == ' ') d->rule->ports.pop_back();

            d->rule->action = (RuleAction)SendDlgItemMessageW(h,IDC_COMBO_RULE_ACTION,CB_GETCURSEL,0,0);
            d->rule->proxy_index = (int)SendDlgItemMessageW(h,IDC_COMBO_RULE_PROXY,CB_GETCURSEL,0,0) - 1;
            d->rule->chain_index = (int)SendDlgItemMessageW(h,IDC_COMBO_RULE_CHAIN,CB_GETCURSEL,0,0) - 1;
            d->rule->enabled = true;
            if (d->rule->name.empty()) {
                if (!d->rule->hosts.empty()) d->rule->name = d->rule->hosts;
                else if (!d->rule->apps.empty()) d->rule->name = d->rule->apps;
                else d->rule->name = "All Traffic";
            }
            d->confirmed = true; EndDialog(h,IDOK); return TRUE;
        }
        if (LOWORD(wp)==IDCANCEL) { EndDialog(h,IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

bool show_rule_dialog(HWND parent, ProxyRule& rule, const ProxyList& proxies,
                      const ProxyChainManager& chains, bool edit_mode) {
    RuleData data{&rule, &proxies, &chains, edit_mode, false};
    DlgBuilder b(330, 370, edit_mode ? L"Edit Rule" : L"Add Rule");

    b.add(SS_LEFT,12,14,60,9,0xFFFF,L"Static",L"Name:");
    b.add(WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,80,12,240,14,IDC_EDIT_RULE_NAME,L"Edit",L"");

    b.add(SS_LEFT,12,36,65,9,0xFFFF,L"Static",L"Applications:");
    b.add(WS_BORDER|WS_TABSTOP|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_WANTRETURN,
          80,34,240,36,IDC_EDIT_RULE_APPS,L"Edit",L"");
    b.add(SS_LEFT,80,72,240,9,0xFFFF,L"Static",
          L"One exe per line. Empty = all apps.");

    b.add(SS_LEFT,12,88,65,9,0xFFFF,L"Static",L"Hosts:");
    b.add(WS_BORDER|WS_TABSTOP|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_WANTRETURN,
          80,86,240,50,IDC_EDIT_RULE_HOSTS,L"Edit",L"");
    b.add(SS_LEFT,80,138,240,9,0xFFFF,L"Static",
          L"One domain/IP per line. Empty = all hosts.");

    b.add(SS_LEFT,12,154,65,9,0xFFFF,L"Static",L"Ports:");
    b.add(WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,80,152,240,14,IDC_EDIT_RULE_PORTS,L"Edit",L"");
    b.add(SS_LEFT,80,168,240,9,0xFFFF,L"Static",
          L"e.g. 80, 443 or 1-1024. Empty = all ports.");

    b.add(SS_LEFT,12,188,60,9,0xFFFF,L"Static",L"Action:");
    b.add(CBS_DROPDOWNLIST|WS_TABSTOP,80,186,240,100,IDC_COMBO_RULE_ACTION,L"ComboBox",L"");

    b.add(SS_LEFT,12,210,60,9,0xFFFF,L"Static",L"Proxy:");
    b.add(CBS_DROPDOWNLIST|WS_TABSTOP,80,208,240,200,IDC_COMBO_RULE_PROXY,L"ComboBox",L"");

    b.add(SS_LEFT,12,232,60,9,0xFFFF,L"Static",L"Chain:");
    b.add(CBS_DROPDOWNLIST|WS_TABSTOP,80,230,240,200,IDC_COMBO_RULE_CHAIN,L"ComboBox",L"");

    b.add(SS_LEFT,12,255,310,18,0xFFFF,L"Static",
          L"All filled fields must match (AND). Empty = match any. Drag to reorder.");

    b.add(BS_DEFPUSHBUTTON|WS_TABSTOP,115,280,65,18,IDOK,L"Button",L"Save");
    b.add(BS_PUSHBUTTON|WS_TABSTOP,190,280,65,18,IDCANCEL,L"Button",L"Cancel");

    DialogBoxIndirectParamW(GetModuleHandle(0), b.finish(), parent, rule_dlg_proc, (LPARAM)&data);
    return data.confirmed;
}

// ============================================================================
// Chain Dialog
// ============================================================================

struct ChainData {
    ProxyChain* chain;
    const ProxyList* proxies;
    bool edit_mode;
    bool confirmed;
};

static INT_PTR CALLBACK chain_dlg_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    auto* d = (ChainData*)GetWindowLongPtr(h, GWLP_USERDATA);

    switch (msg) {
    case WM_INITDIALOG: {
        d = (ChainData*)lp;
        SetWindowLongPtr(h, GWLP_USERDATA, (LONG_PTR)d);

        SetDlgItemTextW(h, IDC_EDIT_CHAIN_NAME, utf8_to_wide(d->chain->name).c_str());
        SendDlgItemMessageW(h, IDC_EDIT_CHAIN_NAME, EM_SETCUEBANNER, TRUE, (LPARAM)L"e.g. Double hop US");

        HWND combo = GetDlgItem(h, IDC_COMBO_CHAIN_ADD);
        for (size_t i = 0; i < d->proxies->size(); ++i) {
            std::wstring label = std::to_wstring(i+1) + L": " +
                utf8_to_wide(d->proxies->proxies()[i].address()) + L" (" +
                proxy_type_to_wstr(d->proxies->proxies()[i].type) + L")";
            SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)label.c_str());
        }
        if (d->proxies->size() > 0) SendMessageW(combo, CB_SETCURSEL, 0, 0);

        HWND list = GetDlgItem(h, IDC_LIST_CHAIN_PROXIES);
        for (int idx : d->chain->proxy_indices) {
            if (idx >= 0 && (size_t)idx < d->proxies->size()) {
                std::wstring label = std::to_wstring(idx+1) + L": " +
                    utf8_to_wide(d->proxies->proxies()[idx].address());
                SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)label.c_str());
            }
        }

        HWND tip = create_tooltip(h);
        add_tooltip(tip, h, GetDlgItem(h, IDC_EDIT_CHAIN_NAME), L"Friendly name for this proxy chain");
        add_tooltip(tip, h, list, L"Traffic flows through these proxies top-to-bottom. Minimum 2 proxies required.");
        add_tooltip(tip, h, combo, L"Select a proxy to add to the chain");

        RECT rc,prc; GetWindowRect(h,&rc); GetWindowRect(GetParent(h),&prc);
        SetWindowPos(h,0,prc.left+(prc.right-prc.left-(rc.right-rc.left))/2,
                     prc.top+(prc.bottom-prc.top-(rc.bottom-rc.top))/2,0,0,SWP_NOSIZE|SWP_NOZORDER);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_BTN_CHAIN_ADD) {
            int sel = (int)SendDlgItemMessageW(h, IDC_COMBO_CHAIN_ADD, CB_GETCURSEL, 0, 0);
            if (sel >= 0 && (size_t)sel < d->proxies->size()) {
                d->chain->proxy_indices.push_back(sel);
                std::wstring label = std::to_wstring(sel+1) + L": " +
                    utf8_to_wide(d->proxies->proxies()[sel].address());
                SendDlgItemMessageW(h, IDC_LIST_CHAIN_PROXIES, LB_ADDSTRING, 0, (LPARAM)label.c_str());
            }
            return TRUE;
        }
        if (LOWORD(wp) == IDC_BTN_CHAIN_REMOVE) {
            int sel = (int)SendDlgItemMessageW(h, IDC_LIST_CHAIN_PROXIES, LB_GETCURSEL, 0, 0);
            if (sel >= 0 && (size_t)sel < d->chain->proxy_indices.size()) {
                d->chain->proxy_indices.erase(d->chain->proxy_indices.begin() + sel);
                SendDlgItemMessageW(h, IDC_LIST_CHAIN_PROXIES, LB_DELETESTRING, sel, 0);
            }
            return TRUE;
        }
        if (LOWORD(wp) == IDOK) {
            wchar_t b[256];
            GetDlgItemTextW(h, IDC_EDIT_CHAIN_NAME, b, 256);
            d->chain->name = wide_to_utf8(b);
            d->chain->enabled = true;
            if (d->chain->name.empty()) d->chain->name = "Chain";
            if (d->chain->proxy_indices.size() < 2) {
                MessageBoxW(h, L"A chain needs at least 2 proxies.", L"Error", MB_ICONWARNING);
                return TRUE;
            }
            d->confirmed = true; EndDialog(h, IDOK); return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(h, IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

bool show_chain_dialog(HWND parent, ProxyChain& chain, const ProxyList& proxies, bool edit_mode) {
    ChainData data{&chain, &proxies, edit_mode, false};
    DlgBuilder b(300, 240, edit_mode ? L"Edit Chain" : L"Add Chain");

    b.add(SS_LEFT, 12, 12, 50, 9, 0xFFFF, L"Static", L"Name:");
    b.add(WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL, 65, 10, 225, 14, IDC_EDIT_CHAIN_NAME, L"Edit", L"");

    b.add(SS_LEFT, 12, 30, 280, 9, 0xFFFF, L"Static", L"Chain order (traffic flows top to bottom):");
    b.add(WS_BORDER|WS_TABSTOP|LBS_NOINTEGRALHEIGHT, 12, 42, 210, 85,
          IDC_LIST_CHAIN_PROXIES, L"ListBox", L"");

    b.add(BS_PUSHBUTTON|WS_TABSTOP, 230, 42, 60, 16, IDC_BTN_CHAIN_REMOVE, L"Button", L"Remove");

    b.add(SS_LEFT, 12, 135, 50, 9, 0xFFFF, L"Static", L"Add:");
    b.add(CBS_DROPDOWNLIST|WS_TABSTOP, 40, 133, 195, 200, IDC_COMBO_CHAIN_ADD, L"ComboBox", L"");
    b.add(BS_PUSHBUTTON|WS_TABSTOP, 240, 133, 50, 16, IDC_BTN_CHAIN_ADD, L"Button", L"Add");

    b.add(SS_LEFT, 12, 160, 280, 9, 0xFFFF, L"Static", L"A chain requires at least 2 proxies for multi-hop routing.");

    b.add(BS_DEFPUSHBUTTON|WS_TABSTOP, 100, 180, 55, 16, IDOK, L"Button", L"Save");
    b.add(BS_PUSHBUTTON|WS_TABSTOP, 165, 180, 55, 16, IDCANCEL, L"Button", L"Cancel");

    DialogBoxIndirectParamW(GetModuleHandle(0), b.finish(), parent, chain_dlg_proc, (LPARAM)&data);
    return data.confirmed;
}

// ============================================================================
// About
// ============================================================================

void show_about_dialog(HWND parent) {
    MessageBoxW(parent,
        L"FlowProxy v1.0\n"
        L"Open Source Proxy Client & Traffic Router\n"
        L"Pure C++ / Win32 API - Zero External Dependencies\n\n"
        L"FEATURES:\n"
        L"  - Route application traffic through proxy servers\n"
        L"  - Application-based routing rules\n"
        L"  - Proxy chain support (multi-hop)\n"
        L"  - System-wide traffic management\n"
        L"  - HTTP / HTTPS / SOCKS4 / SOCKS5 protocols\n"
        L"  - DNS leak prevention (remote DNS resolution)\n"
        L"  - Real-time system connection monitoring\n"
        L"  - Traffic logging with CSV export\n"
        L"  - Proxy checking & rotation\n\n"
        L"Licensed under MIT License\n"
        L"https://github.com/HorusGod007/FlowProxy",
        L"About FlowProxy",
        MB_ICONINFORMATION
    );
}
