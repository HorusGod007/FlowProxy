#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "core/proxy.h"
#include "core/proxy_list.h"
#include "core/checker.h"
#include "core/rules_engine.h"
#include "core/proxy_chain.h"
#include "utils/settings.h"

// Proxy Add/Edit dialog
bool show_proxy_dialog(HWND parent, Proxy& proxy, bool edit_mode,
                       ProxyChecker* checker = nullptr);

// Settings dialog
bool show_settings_dialog(HWND parent, AppSettings& settings);

// Rule Add/Edit dialog
bool show_rule_dialog(HWND parent, ProxyRule& rule, const ProxyList& proxies,
                      const ProxyChainManager& chains, bool edit_mode);

// Chain Add/Edit dialog
bool show_chain_dialog(HWND parent, ProxyChain& chain, const ProxyList& proxies, bool edit_mode);

// About dialog
void show_about_dialog(HWND parent);
