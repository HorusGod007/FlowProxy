#pragma once

// Menu IDs
#define IDM_MAINMENU            100
#define IDM_FILE_IMPORT         101
#define IDM_FILE_EXPORT         102
#define IDM_FILE_SETTINGS       103
#define IDM_FILE_EXIT           104
#define IDM_PROXY_ADD           110
#define IDM_PROXY_EDIT          111
#define IDM_PROXY_DELETE        112
#define IDM_PROXY_DELETE_ALL    113
#define IDM_PROXY_DELETE_DEAD   114
#define IDM_CHECK_ALL           120
#define IDM_CHECK_SELECTED      121
#define IDM_CHECK_STOP          122
#define IDM_TOOLS_SET_SYSTEM    132
#define IDM_TOOLS_CLEAR_SYSTEM  133
#define IDM_HELP_ABOUT          140

// Rules menu
#define IDM_RULES_ADD           150
#define IDM_RULES_EDIT          151
#define IDM_RULES_DELETE        152
#define IDM_RULES_MANAGE        153
#define IDM_RULES_UP            154
#define IDM_RULES_DOWN          155

// Chain menu
#define IDM_CHAIN_ADD           160
#define IDM_CHAIN_EDIT          161
#define IDM_CHAIN_DELETE        162
#define IDM_CHAIN_MANAGE        163

// View menu
#define IDM_VIEW_CONNECTIONS    170
#define IDM_VIEW_TRAFFIC_LOG    171
#define IDM_VIEW_STATS          172
#define IDM_VIEW_EXPORT_LOGS    173
#define IDM_VIEW_CLEAR_LOGS     174

// DNS menu
#define IDM_DNS_LOCAL           180
#define IDM_DNS_REMOTE          181
#define IDM_DNS_CUSTOM          182
#define IDM_DNS_FLUSH_CACHE     183

// Toolbar button IDs
#define IDT_TOOLBAR             200
#define IDB_ADD                 IDM_PROXY_ADD
#define IDB_DELETE              IDM_PROXY_DELETE
#define IDB_CHECK_ALL           IDM_CHECK_ALL
#define IDB_CHECK_SEL           IDM_CHECK_SELECTED
#define IDB_STOP                IDM_CHECK_STOP
#define IDB_IMPORT              IDM_FILE_IMPORT
#define IDB_EXPORT              IDM_FILE_EXPORT
#define IDB_TUNNEL              IDM_TOOLS_SET_SYSTEM

// Status bar
#define IDS_STATUSBAR           300

// Main tab control
#define IDC_TAB_CONTROL         350

// ListViews (one per tab)
#define IDC_LISTVIEW            400
#define IDC_LV_RULES            401
#define IDC_LV_CHAINS           402
#define IDC_LV_CONNECTIONS      403
#define IDC_LV_LOGS             404
#define IDC_LV_PROXIED          405

// Rule dialog extras
#define IDC_EDIT_RULE_APPS      810
#define IDC_EDIT_RULE_HOSTS     811
#define IDC_EDIT_RULE_PORTS     812

// Dialog IDs
#define IDD_PROXY_EDIT          500
#define IDC_EDIT_HOST           501
#define IDC_EDIT_PORT           502
#define IDC_COMBO_TYPE          503
#define IDC_EDIT_USER           504
#define IDC_EDIT_PASS           505

#define IDD_SETTINGS            600
#define IDC_EDIT_THREADS        601
#define IDC_EDIT_TIMEOUT        602
#define IDC_EDIT_TEST_URL       603
#define IDC_EDIT_SERVER_PORT    604
#define IDC_COMBO_ROTATION      605
#define IDC_EDIT_SOCKS_PORT     606
#define IDC_COMBO_DNS_MODE      607
#define IDC_EDIT_DNS_SERVER     608

#define IDD_ABOUT               700

#define IDD_RULE_EDIT           800
#define IDC_EDIT_RULE_NAME      801
#define IDC_COMBO_RULE_TARGET   802
#define IDC_EDIT_RULE_PATTERN   803
#define IDC_COMBO_RULE_ACTION   804
#define IDC_COMBO_RULE_PROXY    805
#define IDC_COMBO_RULE_CHAIN    806
#define IDC_CHECK_RULE_ENABLED  807

#define IDD_CHAIN_EDIT          900
#define IDC_EDIT_CHAIN_NAME     901
#define IDC_LIST_CHAIN_PROXIES  902
#define IDC_COMBO_CHAIN_ADD     903
#define IDC_BTN_CHAIN_ADD       904
#define IDC_BTN_CHAIN_REMOVE    905
#define IDC_BTN_CHAIN_UP        906
#define IDC_BTN_CHAIN_DOWN      907

// Proxy dialog extras
#define IDC_BTN_CHECK_PROXY     510
#define IDC_STATIC_CHECK_RESULT 511

// Timer IDs
#define IDT_STATS_REFRESH       1001
#define IDT_RATE_UPDATE         1002

// Custom messages
#define WM_PROXY_CHECK_DONE     (WM_USER + 1)
#define WM_PROXY_CHECK_UPDATE   (WM_USER + 2)
#define WM_SERVER_STATUS        (WM_USER + 3)
#define WM_CONNECTION_UPDATE    (WM_USER + 4)
#define WM_TRAY_ICON            (WM_USER + 10)

// Tray menu
#define IDM_TRAY_RESTORE        1050
#define IDM_TRAY_EXIT           1051

// App icon
#define IDI_APP_ICON            1000
