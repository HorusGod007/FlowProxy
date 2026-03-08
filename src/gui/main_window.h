#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>

#include "core/proxy_list.h"
#include "core/checker.h"
#include "core/importer.h"
#include "core/rules_engine.h"
#include "core/proxy_chain.h"
#include "net/local_server.h"
#include "net/traffic_interceptor.h"
#include "net/dns_resolver.h"
#include "net/connection_monitor.h"
#include "utils/settings.h"
#include "utils/system_proxy.h"

class MainWindow {
public:
    MainWindow();
    ~MainWindow();

    bool create(HINSTANCE hInstance, int nCmdShow);
    static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    HWND handle() const { return hwnd_; }

private:
    // Window setup
    void create_menu();
    void create_toolbar();
    void create_tab_control();
    void create_proxy_listview();
    void create_rules_listview();
    void create_connections_listview();
    void create_logs_listview();
    void create_statusbar();
    void update_layout();
    void on_tab_changed();

    // ListView operations
    void refresh_proxy_list();
    void refresh_rules_list();
    void refresh_connections_list();
    void refresh_logs_list();
    void update_listview_item(int index);
    void update_statusbar();

    // Proxy commands
    void on_proxy_add();
    void on_proxy_edit();
    void on_proxy_delete();
    void on_proxy_delete_all();
    void on_proxy_delete_dead();
    void on_check_all();
    void on_check_selected();
    void on_check_stop();
    void on_import();
    void on_export();
    void on_settings();

    // Routing commands
    void on_enable_routing();
    void on_disable_routing();

    // Rules commands
    void on_rule_add();
    void on_rule_edit();
    void on_rule_delete();
    void on_rule_move_up();
    void on_rule_move_down();

    // Chain commands
    void on_chain_add();
    void on_chain_edit();
    void on_chain_delete();

    // View commands
    void on_view_stats();
    void on_export_logs();
    void on_clear_logs();

    // DNS commands
    void on_dns_mode(DnsMode mode);
    void on_dns_flush();

    void on_about();

    // Helpers
    std::vector<size_t> get_selected_indices(HWND lv);
    std::string open_file_dialog(bool save, const char* filter, const char* default_ext);

    // Tray icon
    void create_tray_icon();
    void remove_tray_icon();
    void minimize_to_tray();
    void restore_from_tray();
    void on_tray_icon(LPARAM lParam);

    // Theme
    void apply_dark_theme();
    LRESULT on_listview_custom_draw(LPARAM lParam);
    LRESULT on_toolbar_custom_draw(LPARAM lParam);
    void draw_tab_item(LPDRAWITEMSTRUCT dis);
    void draw_statusbar_part(LPDRAWITEMSTRUCT dis);

    // Message handlers
    LRESULT handle_message(UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT on_notify(LPARAM lParam);
    void on_command(WPARAM wParam);
    void on_context_menu(HWND hwnd, int x, int y);
    void on_timer(WPARAM timer_id);

    HWND hwnd_ = nullptr;
    HWND toolbar_ = nullptr;
    HWND tab_control_ = nullptr;
    HWND lv_proxies_ = nullptr;
    HWND lv_rules_ = nullptr;
    HWND lv_connections_ = nullptr;
    HWND lv_logs_ = nullptr;
    HWND statusbar_ = nullptr;
    HMENU menu_ = nullptr;
    HINSTANCE hinstance_ = nullptr;
    int current_tab_ = 0;

    // Core systems
    ProxyList proxy_list_;
    ProxyChecker checker_;
    RulesEngine rules_engine_;
    ProxyChainManager chain_manager_;
    DnsResolver dns_resolver_;
    ConnectionMonitor conn_monitor_;
    LocalProxyServer* server_ = nullptr;
    TrafficInterceptor* interceptor_ = nullptr;
    AppSettings settings_;
    bool routing_active_ = false;

    SortColumn sort_column_ = SortColumn::Host;
    bool sort_ascending_ = true;
    NOTIFYICONDATAW nid_ = {};
    bool in_tray_ = false;

    // Rule drag & drop reordering
    bool dragging_rule_ = false;
    int drag_rule_index_ = -1;
};
