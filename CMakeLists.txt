cmake_minimum_required(VERSION 3.15)
project(FlowProxy VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    add_compile_definitions(UNICODE _UNICODE)
endif()

# ============================================================================
# FlowProxy.exe - Main application
# ============================================================================

set(SOURCES
    src/main.cpp
    src/core/proxy.cpp
    src/core/proxy_list.cpp
    src/core/checker.cpp
    src/core/importer.cpp
    src/core/rules_engine.cpp
    src/core/proxy_chain.cpp
    src/net/socket.cpp
    src/net/socks.cpp
    src/net/local_server.cpp
    src/net/traffic_interceptor.cpp
    src/net/dns_resolver.cpp
    src/net/connection_monitor.cpp
    src/gui/main_window.cpp
    src/gui/dialogs.cpp
    src/gui/theme.cpp
    src/utils/settings.cpp
    src/utils/system_proxy.cpp
)

set(HEADERS
    src/core/proxy.h
    src/core/proxy_list.h
    src/core/checker.h
    src/core/importer.h
    src/core/rules_engine.h
    src/core/proxy_chain.h
    src/net/socket.h
    src/net/socks.h
    src/net/local_server.h
    src/net/traffic_interceptor.h
    src/net/dns_resolver.h
    src/net/connection_monitor.h
    src/gui/main_window.h
    src/gui/dialogs.h
    src/gui/theme.h
    src/utils/settings.h
    src/utils/system_proxy.h
    resources/resource.h
)

add_executable(FlowProxy WIN32 ${SOURCES} ${HEADERS} resources/app.rc)

target_include_directories(FlowProxy PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR})
target_link_libraries(FlowProxy PRIVATE
    ws2_32 wininet comctl32 shlwapi iphlpapi rpcrt4 psapi comdlg32 dwmapi uxtheme
)

if(NOT MSVC)
    target_link_options(FlowProxy PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()

install(TARGETS FlowProxy RUNTIME DESTINATION bin)
