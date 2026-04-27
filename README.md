# dnsman

Windows DNS management CLI written in Go.  
**Zero PowerShell. Zero `net.exe`. Zero `ipconfig`.**  
Every operation calls Windows APIs directly.

---

## How it works internally

| Operation | Windows API / mechanism |
|---|---|
| List adapters / read active DNS | `GetAdaptersAddresses()` (iphlpapi.dll) |
| Read static / DHCP DNS settings | Windows Registry via `golang.org/x/sys/windows/registry` |
| Write static DNS servers | Windows Registry (`HKLM\SYSTEM\...\Tcpip\Parameters\Interfaces\<GUID>\NameServer`) |
| Flush DNS resolver cache | `DnsFlushResolverCache()` from `dnsapi.dll` (direct DLL call) |
| Restart `dnscache` / `named` | Service Control Manager via `golang.org/x/sys/windows/svc/mgr` |
| DNS resolution test | Go standard `net.LookupHost` / `net.LookupAddr` |

No shell, no external processes, no dependencies on PowerShell being installed.

---

## Features

| Command | Description |
|---|---|
| `adapters` | List all adapters (DHCP vs Static) |
| `show` | Display DNS for all adapters or one specific interface |
| `set` | Set static DNS via Registry; supports presets and fallback flags |
| `flush` | Flush resolver cache via `DnsFlushResolverCache()` |
| `restart` | Restart `dnscache` (optionally `named`) via SCM, then flush |
| `reset` | Clear static DNS, revert to DHCP |
| `test` | Resolve a hostname — shows IPs, timing, and PTR record |
| `presets` | List 7 built-in DNS provider presets |
| `version` | Print version, commit, build date |

---

## Installation

### Prerequisites
- Go 1.22+
- Windows 10 / 11
- Run as **Administrator** for write operations (set, reset, flush, restart)

### Build

```bash
# Get dependencies
go mod tidy

# Build for Windows (cross-compile from any OS)
make build-windows        # → dnsman.exe

# Or natively on Windows
go build -o dnsman.exe .
```

### Optional: add to PATH

```cmd
copy dnsman.exe C:\Windows\System32\
```

---

## Usage

> Commands that modify state require an elevated (Administrator) terminal.

### `adapters` — list all network adapters

```cmd
dnsman adapters
```

Output shows each adapter's friendly name, DNS mode (DHCP/Static), and description.  
Use these names with the `--interface` / `-i` flag.

### `show` — display current DNS

```cmd
dnsman show                    # all adapters with DNS configured
dnsman show -i "Wi-Fi"
dnsman show -i "Ethernet"
dnsman show -i "vEthernet (wifi)"
dnsman show -i "*Ethernet*"
dnsman show -i "*wi-fi*"
```

Shows: static DNS, DHCP-assigned DNS, active IPv4/IPv6 DNS, DHCP enabled flag.

### `set` — set static DNS servers

```cmd
# Single custom server
dnsman set 192.168.1.53

# Built-in preset
dnsman set --preset cloudflare
dnsman set --preset quad9

# Custom primary + preset fallbacks
dnsman set 192.168.1.53 --preset cloudflare

# Custom primary + auto-append 1.1.1.1, 8.8.8.8, 8.8.4.4
dnsman set 192.168.1.53 --fallback

# Different interface
dnsman set --preset google -i "Ethernet"
```

**Built-in presets:**

| Name | Servers |
|---|---|
| `cloudflare` | 1.1.1.1, 1.0.0.1 |
| `google` | 8.8.8.8, 8.8.4.4 |
| `quad9` | 9.9.9.9, 149.112.112.112 |
| `opendns` | 208.67.222.222, 208.67.220.220 |
| `adguard` | 94.140.14.14, 94.140.15.15 |
| `nextdns` | 45.90.28.0, 45.90.30.0 |
| `cleanbrowsing` | 185.228.168.9, 185.228.169.9 |

### `flush` — flush resolver cache

```cmd
dnsman flush
```

Calls `DnsFlushResolverCache()` from `dnsapi.dll` directly.

### `restart` — restart DNS services

```cmd
dnsman restart           # restarts dnscache, then flushes
dnsman restart --named   # also restarts BIND named service
```

Uses the Windows Service Control Manager — no `net stop/start` commands.

### `reset` — revert to DHCP

```cmd
dnsman reset
dnsman reset -i "Ethernet"
```

Clears the `NameServer` registry value, making the adapter use DHCP-assigned DNS again.

### `test` — test DNS resolution

```cmd
dnsman test
dnsman test google.com
dnsman test --host github.com
```

Shows resolved IPv4/IPv6 addresses, resolution time in ms, and reverse PTR record.

### `presets` — list presets

```cmd
dnsman presets
```

### `version`

```cmd
dnsman version
```

---

## Default interface

`vEthernet (wifi)` — override with `--interface` / `-i` on any command that needs it.  
Run `dnsman adapters` to see all available interface names.

---

## Build flags

Version info is injected at compile time:

```bash
go build -ldflags "-s -w -X main.version=1.0.0 -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o dnsman.exe .
```

Or use `make build-windows` — the Makefile does this automatically.

---

## Dependencies

| Package | Purpose |
|---|---|
| `golang.org/x/sys/windows` | `GetAdaptersAddresses`, Win32 types, `dnsapi.dll` |
| `golang.org/x/sys/windows/registry` | Registry read/write |
| `golang.org/x/sys/windows/svc/mgr` | Service Control Manager |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/fatih/color` | Colorized terminal output |

---

## License

MIT

## 👤 Author
        
[Hadi Cahyadi](mailto:cumulus13@gmail.com)
    

[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/cumulus13)

[![Donate via Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cumulus13)
 
[Support me on Patreon](https://www.patreon.com/cumulus13)