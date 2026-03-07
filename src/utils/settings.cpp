#include "utils/settings.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>

#include <fstream>
#include <sstream>

#pragma comment(lib, "shlwapi.lib")

std::string Settings::get_config_path() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        std::string dir = std::string(path) + "\\FlowProxy";
        CreateDirectoryA(dir.c_str(), nullptr);
        return dir + "\\settings.ini";
    }
    return "settings.ini";
}

std::string Settings::get_proxy_save_path() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        std::string dir = std::string(path) + "\\FlowProxy";
        CreateDirectoryA(dir.c_str(), nullptr);
        return dir + "\\proxies.txt";
    }
    return "proxies.txt";
}

std::string Settings::read_ini_value(const std::string& filepath, const std::string& section,
                                     const std::string& key, const std::string& default_val) {
    char buf[1024];
    GetPrivateProfileStringA(section.c_str(), key.c_str(), default_val.c_str(),
                             buf, sizeof(buf), filepath.c_str());
    return std::string(buf);
}

void Settings::write_ini_value(const std::string& filepath, const std::string& section,
                               const std::string& key, const std::string& value) {
    WritePrivateProfileStringA(section.c_str(), key.c_str(), value.c_str(), filepath.c_str());
}

bool Settings::load(AppSettings& settings) {
    std::string path = get_config_path();

    settings.checker_threads = std::stoi(read_ini_value(path, "Checker", "Threads", "10"));
    settings.checker_timeout = std::stoi(read_ini_value(path, "Checker", "Timeout", "5000"));
    settings.test_url = read_ini_value(path, "Checker", "TestURL", "http://httpbin.org/ip");

    settings.server_port = (uint16_t)std::stoi(read_ini_value(path, "Server", "Port", "8080"));
    settings.rotation_mode = (RotationMode)std::stoi(read_ini_value(path, "Server", "Rotation", "0"));

    settings.window_x = std::stoi(read_ini_value(path, "Window", "X", "100"));
    settings.window_y = std::stoi(read_ini_value(path, "Window", "Y", "100"));
    settings.window_w = std::stoi(read_ini_value(path, "Window", "W", "1024"));
    settings.window_h = std::stoi(read_ini_value(path, "Window", "H", "600"));

    settings.last_import_path = read_ini_value(path, "Paths", "LastImport", "");
    settings.last_export_path = read_ini_value(path, "Paths", "LastExport", "");

    return true;
}

bool Settings::save(const AppSettings& settings) {
    std::string path = get_config_path();

    write_ini_value(path, "Checker", "Threads", std::to_string(settings.checker_threads));
    write_ini_value(path, "Checker", "Timeout", std::to_string(settings.checker_timeout));
    write_ini_value(path, "Checker", "TestURL", settings.test_url);

    write_ini_value(path, "Server", "Port", std::to_string(settings.server_port));
    write_ini_value(path, "Server", "Rotation", std::to_string((int)settings.rotation_mode));

    write_ini_value(path, "Window", "X", std::to_string(settings.window_x));
    write_ini_value(path, "Window", "Y", std::to_string(settings.window_y));
    write_ini_value(path, "Window", "W", std::to_string(settings.window_w));
    write_ini_value(path, "Window", "H", std::to_string(settings.window_h));

    write_ini_value(path, "Paths", "LastImport", settings.last_import_path);
    write_ini_value(path, "Paths", "LastExport", settings.last_export_path);

    return true;
}
