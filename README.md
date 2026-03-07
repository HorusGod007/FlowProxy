# FlowProxy

A lightweight, high-performance proxy client and traffic router for Windows. Built entirely in C++ with the Win32 API — zero external dependencies.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![Language](https://img.shields.io/badge/language-C%2B%2B17-orange.svg)

---

## Features

- **Application-Based Routing** — Create rules to route specific applications (e.g., `firefox.exe`) through proxy servers while other apps connect directly
- **Multi-Protocol Support** — HTTP, HTTPS, SOCKS4, and SOCKS5 proxy protocols with authentication
- **Proxy Chains** — Route traffic through multiple proxies in sequence (multi-hop)
- **Real-Time Connection Monitor** — View all system TCP connections with process names, similar to Proxifier
- **Traffic Logging** — Full connection logging with CSV export support
- **Proxy Checker** — Bulk check proxy servers for availability, latency, and anonymity level
- **Proxy Rotation** — Automatic rotation across multiple proxies (round-robin, random, or least-used)
- **DNS Leak Prevention** — Remote DNS resolution through SOCKS5 proxies or custom DNS servers
- **System Tray** — Minimizes to tray with quick routing toggle
- **Lightweight** — Single portable executable, no installation required, no runtime dependencies

## Screenshots

*Coming soon*

## How It Works

FlowProxy runs a local interceptor and configures the Windows system proxy to route HTTP/HTTPS traffic through it. The interceptor evaluates your routing rules for each connection:

- **Rule matches** → Traffic is routed through the specified proxy or chain
- **No rule matches** → Traffic passes through directly (zero overhead for unmatched apps)
- **Block rule** → Connection is rejected

Applications using WinINET or WinHTTP (browsers, most desktop apps) are automatically routed. Apps using raw sockets bypass the system proxy and are unaffected.

## Installation

### Download

Grab the latest release from the [Releases](https://github.com/HorusGod007/FlowProxy/releases) page. No installation needed — just run `FlowProxy.exe`.

### Build from Source

**Requirements:**
- CMake 3.15+
- MSVC (Visual Studio 2019+) or MinGW-w64
- Windows SDK

**MSVC:**
```bash
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022"
cmake --build . --config Release
```

**MinGW-w64:**
```bash
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../toolchain-mingw64.cmake
make -j$(nproc)
```

**Cross-compile from Linux:**
```bash
# Install MinGW-w64 toolchain
sudo apt install mingw-w64

mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../toolchain-mingw64.cmake
make -j$(nproc)
```

The output binary `FlowProxy.exe` will be in the `build/` directory.

## Usage

### Quick Start

1. Launch `FlowProxy.exe` — routing starts automatically
2. Go to the **Proxies** tab and add your proxy servers
3. Go to the **Rules** tab and create routing rules
4. Check the **Connections** tab to see all system traffic in real time

### Adding Proxies

**Menu:** Proxy → Add Proxy (or press `Insert`)

Enter the proxy host, port, type (HTTP/HTTPS/SOCKS4/SOCKS5), and optional credentials. Click **Check** to test connectivity before saving.

### Creating Rules

**Menu:** Rules → Add Rule

| Field | Description |
|-------|-------------|
| **Name** | Display name for the rule |
| **Target** | What to match: Application, Domain, IP, Port, or All |
| **Pattern** | Match pattern — supports wildcards (`*`, `?`) |
| **Action** | Use Proxy, Direct (bypass), Block, or Use Chain |
| **Proxy** | Specific proxy or auto-rotation |
| **Priority** | Lower number = higher priority |

**Examples:**

| Rule | Target | Pattern | Action |
|------|--------|---------|--------|
| Firefox via proxy | Application | `firefox.exe` | Use Proxy |
| Block telemetry | Domain | `*.telemetry.*` | Block |
| Direct for local | IP | `192.168.0.0/16` | Direct |
| Secure browsing | Port | `443` | Use Proxy |

### Tabs

| Tab | Description |
|-----|-------------|
| **Proxies** | Manage proxy servers — add, edit, delete, check, import/export |
| **Rules** | Configure routing rules per application, domain, IP, or port |
| **Connections** | Live view of all system TCP connections with process info |
| **Logs** | Traffic log showing proxied and direct connections |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Insert` | Add new proxy/rule |
| `Delete` | Delete selected |
| `Enter` | Edit selected |
| `Ctrl+I` | Import proxies |
| `Ctrl+E` | Export proxies |
| `Ctrl+S` | Settings |

### DNS Modes

**Menu:** Tools → DNS

| Mode | Description |
|------|-------------|
| **Local DNS** | Uses system DNS (default, fastest) |
| **Remote DNS** | DNS resolution through SOCKS5 proxy (prevents DNS leaks) |
| **Custom DNS** | Route DNS queries to a custom server through proxy |

## Project Structure

```
FlowProxy/
├── src/
│   ├── core/           # Proxy model, checker, importer, rules engine, chains
│   ├── net/            # Socket, SOCKS protocol, interceptor, DNS resolver, connection monitor
│   ├── gui/            # Win32 main window, dialogs, theme
│   ├── utils/          # Settings (INI), system proxy (registry)
│   └── main.cpp        # Entry point
├── resources/          # Win32 resources, icon, manifest
├── CMakeLists.txt      # Build configuration
└── LICENSE             # MIT License
```

## Technical Details

- **Language:** C++17
- **GUI Framework:** Pure Win32 API (no MFC, no ATL, no Qt)
- **Networking:** Winsock2 (ws2_32)
- **System Proxy:** WinINET registry + `InternetSetOption` API
- **Connection Monitoring:** `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_ALL`
- **Process Detection:** `QueryFullProcessImageName` via TCP table PID lookup
- **Linked Libraries:** ws2_32, wininet, comctl32, shlwapi, iphlpapi, psapi, comdlg32, dwmapi, uxtheme

## Limitations

- **UWP/Store apps** cannot connect to loopback addresses due to AppContainer isolation — they won't be routed through FlowProxy
- **Raw socket applications** that don't use WinINET/WinHTTP will bypass the system proxy
- **Non-TCP traffic** (UDP, ICMP) is not intercepted

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
