#pragma once

#include "core/checker.h"
#include "core/proxy_list.h"
#include <string>

struct AppSettings {
    // Checker
    int checker_threads = 10;
    int checker_timeout = 5000;
    std::string test_url = "http://httpbin.org/ip";

    // Local server
    uint16_t server_port = 8080;
    RotationMode rotation_mode = RotationMode::RoundRobin;

    // Window
    int window_x = 100;
    int window_y = 100;
    int window_w = 1024;
    int window_h = 600;

    // Last file
    std::string last_import_path;
    std::string last_export_path;
};

class Settings {
public:
    static std::string get_config_path();
    static std::string get_proxy_save_path();

    static bool load(AppSettings& settings);
    static bool save(const AppSettings& settings);

private:
    static std::string read_ini_value(const std::string& filepath, const std::string& section, const std::string& key, const std::string& default_val);
    static void write_ini_value(const std::string& filepath, const std::string& section, const std::string& key, const std::string& value);
};
