#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commctrl.h>

#include "net/socket.h"
#include "gui/main_window.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialize common controls (for ListView, Toolbar, StatusBar)
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    // Initialize WinSock
    if (!Socket::init_winsock()) {
        MessageBoxW(nullptr, L"Failed to initialize WinSock.", L"Fatal Error", MB_ICONERROR);
        return 1;
    }

    // Create and show main window
    MainWindow main_window;
    if (!main_window.create(hInstance, nCmdShow)) {
        Socket::cleanup_winsock();
        MessageBoxW(nullptr, L"Failed to create main window.", L"Fatal Error", MB_ICONERROR);
        return 1;
    }

    // Message loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    Socket::cleanup_winsock();
    return (int)msg.wParam;
}
