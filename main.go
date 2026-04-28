	// dnsman: Windows DNS manager — zero PowerShell, zero net.exe, zero ipconfig.
//
// Implementation uses only:
//   - Windows Registry  (golang.org/x/sys/windows/registry)   → read/write DNS servers
//   - Service Control Manager (golang.org/x/sys/windows/svc)  → restart dnscache/named
//   - DnsApi.dll  DnsFlushResolverCache()                      → flush DNS cache
//   - GetAdaptersAddresses() Win32 API via iphlpapi.dll        → enumerate adapters
//   - Go standard net package                                  → DNS test/resolution
//
// Build (Windows only):
//   GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.version=1.0.0" -o dnsman.exe .
//
//go:build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ── Version (injected via -ldflags) ─────────────────────────────────────────

var (
	version = "1.0.3"
	commit  = "dev"
	date    = "2026/04/27"
	author  = "Hadi Cahyadi"
	email   = "cumulus13@gmail.com"
	homepage = "github.com/cumulus13/dnsman"
)

// ── DNS presets ──────────────────────────────────────────────────────────────

var dnsPresets = map[string][]string{
	"cloudflare":    {"1.1.1.1", "1.0.0.1"},
	"google":        {"8.8.8.8", "8.8.4.4"},
	"quad9":         {"9.9.9.9", "149.112.112.112"},
	"opendns":       {"208.67.222.222", "208.67.220.220"},
	"adguard":       {"94.140.14.14", "94.140.15.15"},
	"nextdns":       {"45.90.28.0", "45.90.30.0"},
	"cleanbrowsing": {"185.228.168.9", "185.228.169.9"},
}

// Registry path where Windows stores per-adapter TCP/IP settings.
const tcpipParamsPath = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`

// ── Styling ──────────────────────────────────────────────────────────────────

var (
	bold    = color.New(color.Bold)
	green   = color.New(color.FgGreen, color.Bold)
	yellow  = color.New(color.FgYellow, color.Bold)
	red     = color.New(color.FgRed, color.Bold)
	cyan    = color.New(color.FgCyan, color.Bold)
	magenta = color.New(color.FgMagenta, color.Bold)
	dim     = color.New(color.Faint)
)

func sep()                  { dim.Println("  " + strings.Repeat("─", 60)) }
func okMsg(msg string)      { green.Printf("  ✔  %s\n", msg) }
func failMsg(msg string)    { red.Printf("  ✖  %s\n", msg) }
func warnMsg(msg string)    { yellow.Printf("  ⚠  %s\n", msg) }
func infoMsg(msg string)    { cyan.Printf("  ℹ  %s\n", msg) }
func stepMsg(icon, msg string) { fmt.Printf("  %s  %s\n", icon, msg) }

// label prints a fixed-width left-column label + value on the same line.
// col is the visual column width for the label (no color codes).
func label(col int, key, val string) {
	fmt.Printf("  %-*s  %s\n", col, key, val)
}

func printBanner() {
	cyan.Println(`
  ██████╗ ███╗   ██╗███████╗    ███╗   ███╗ ██████╗ ██████╗
  ██╔══██╗████╗  ██║██╔════╝    ████╗ ████║██╔════╝ ██╔══██╗
  ██║  ██║██╔██╗ ██║███████╗    ██╔████╔██║██║  ███╗██████╔╝
  ██║  ██║██║╚██╗██║╚════██║    ██║╚██╔╝██║██║   ██║██╔══██╗
  ██████╔╝██║ ╚████║███████║    ██║ ╚═╝ ██║╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝`)
	dim.Printf("  DNS Manager v%s (%s) — built %s by %s\n\n", version, commit, date, author)
}

// ── Adapter enumeration via GetAdaptersAddresses ─────────────────────────────

// Adapter holds resolved info about one network interface.
type Adapter struct {
	Name        string // friendly name e.g. "Wi-Fi"
	GUID        string // registry GUID e.g. "{4D36E972-...}"
	Description string
	IPv4DNS     []string
	IPv6DNS     []string
	DHCPEnabled bool
	IsLoopback  bool
}

// procGetAdaptersAddresses is loaded via lazy DLL to call with raw uintptr
// return values, avoiding the type mismatch in the golang.org/x/sys wrapper
// (which returns error instead of the Win32 DWORD we need for buffer-overflow
// retry logic).
var (
	iphlpapi                 = windows.NewLazyDLL("iphlpapi.dll")
	procGetAdaptersAddresses = iphlpapi.NewProc("GetAdaptersAddresses")
)

// getAdapters calls GetAdaptersAddresses and returns all adapters keyed by friendly name.
func getAdapters() (map[string]*Adapter, error) {
	const (
		errBufferOverflow = uintptr(111) // ERROR_BUFFER_OVERFLOW
		errNoData         = uintptr(232) // ERROR_NO_DATA
		afUnspec          = uintptr(0)
		// GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST
		flags = uintptr(0x0010 | 0x0004 | 0x0008)
	)

	size := uint32(20000)
	var buf []byte

	for {
		buf = make([]byte, size)
		r1, _, _ := procGetAdaptersAddresses.Call(
			afUnspec,
			flags,
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		if r1 == errBufferOverflow {
			size *= 2
			continue
		}
		if r1 == errNoData {
			return map[string]*Adapter{}, nil
		}
		if r1 != 0 {
			return nil, fmt.Errorf("GetAdaptersAddresses failed (0x%X): %w", r1, windows.Errno(r1))
		}
		break
	}

	adapters := map[string]*Adapter{}

	for addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); addr != nil; addr = addr.Next {
		friendly := windows.UTF16PtrToString(addr.FriendlyName)
		desc := windows.UTF16PtrToString(addr.Description)
		guid := windows.BytePtrToString(addr.AdapterName)

		a := &Adapter{
			Name:        friendly,
			GUID:        guid,
			Description: desc,
			DHCPEnabled: isDHCP(guid),
			// IfType 24 = SOFTWARE_LOOPBACK
			IsLoopback: addr.IfType == 24,
		}

		// Collect DNS server addresses from the linked list.
		for dns := addr.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			sa := dns.Address.Sockaddr
			if sa == nil {
				continue
			}
			switch sa.Addr.Family {
			case windows.AF_INET:
				raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa))
				a.IPv4DNS = append(a.IPv4DNS, net.IP(raw.Addr[:]).String())
			case windows.AF_INET6:
				raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa))
				ip := net.IP(raw.Addr[:])
				// Skip link-local (fe80::) — they are interface-specific noise.
				if !ip.IsLinkLocalUnicast() {
					a.IPv6DNS = append(a.IPv6DNS, ip.String())
				}
			}
		}

		adapters[friendly] = a
	}
	return adapters, nil
}

// isDHCP reads the registry EnableDHCP flag for a GUID.
func isDHCP(guid string) bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		tcpipParamsPath+`\`+guid, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	val, _, err := key.GetIntegerValue("EnableDHCP")
	return err == nil && val == 1
}

// matchAdapters resolves a pattern against all adapter friendly names and
// returns every adapter that matches.  Resolution order:
//
//  1. Exact match (case-insensitive) — fastest path, always tried first.
//  2. Glob / wildcard  (e.g. *VMnet*, Wi-Fi?, Ethernet*) using path.Match
//     semantics: * matches any sequence, ? matches one character.
//  3. Regular expression (e.g. (?i)vmnet\d+) — tried if the pattern
//     contains regex meta-characters that aren't valid glob syntax.
//
// All comparisons are case-insensitive for exact and glob; regex must embed
// (?i) itself if case-insensitivity is desired.
func matchAdapters(pattern string, adapters map[string]*Adapter) ([]*Adapter, error) {
	lowerPat := strings.ToLower(pattern)

	// ── 1. Exact match ───────────────────────────────────────────────────────
	for name, a := range adapters {
		if strings.ToLower(name) == lowerPat {
			return []*Adapter{a}, nil
		}
	}

	// ── 2. Glob / wildcard ───────────────────────────────────────────────────
	// Only attempt glob if the pattern contains * or ?.
	isGlob := strings.ContainsAny(pattern, "*?")
	if isGlob {
		var matched []*Adapter
		for name, a := range adapters {
			ok, err := globMatch(lowerPat, strings.ToLower(name))
			if err != nil {
				// Invalid glob — fall through to regex.
				isGlob = false
				break
			}
			if ok {
				matched = append(matched, a)
			}
		}
		if isGlob {
			sort.Slice(matched, func(i, j int) bool { return matched[i].Name < matched[j].Name })
			return matched, nil
		}
	}

	// ── 3. Regular expression ────────────────────────────────────────────────
	re, err := regexp.Compile(pattern)
	if err != nil {
		// Not valid regex either — report as not found.
		return nil, adapterNotFoundErr(pattern, adapters)
	}
	var matched []*Adapter
	for name, a := range adapters {
		if re.MatchString(name) {
			matched = append(matched, a)
		}
	}
	if len(matched) == 0 {
		return nil, adapterNotFoundErr(pattern, adapters)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Name < matched[j].Name })
	return matched, nil
}

// globMatch implements simple * / ? wildcard matching (case already folded by caller).
// It does NOT use path.Match to avoid the restriction that * doesn't match /.
func globMatch(pattern, name string) (bool, error) {
	// Convert glob to a simple recursive matcher.
	return globMatchRec(pattern, name), nil
}

func globMatchRec(pat, s string) bool {
	for len(pat) > 0 {
		switch pat[0] {
		case '*':
			// Skip consecutive stars.
			for len(pat) > 0 && pat[0] == '*' {
				pat = pat[1:]
			}
			if len(pat) == 0 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globMatchRec(pat, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			pat = pat[1:]
			s = s[1:]
		default:
			if len(s) == 0 || pat[0] != s[0] {
				return false
			}
			pat = pat[1:]
			s = s[1:]
		}
	}
	return len(s) == 0
}

func adapterNotFoundErr(pattern string, adapters map[string]*Adapter) error {
	var names []string
	for name := range adapters {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Errorf(
		"no interface matched %q\n  Run 'dnsman adapters' to see available names\n  Available: %s",
		pattern, strings.Join(names, ", "),
	)
}

// resolveGUID finds the registry GUID for a pattern (exact/glob/regex).
// When the pattern matches multiple adapters, the first (alphabetically) is used
// and a warning is printed. Use cmdShow to see all matches.
func resolveGUID(pattern string) (string, string, error) {
	adapters, err := getAdapters()
	if err != nil {
		return "", "", err
	}
	matched, err := matchAdapters(pattern, adapters)
	if err != nil {
		return "", "", err
	}
	if len(matched) > 1 {
		var names []string
		for _, a := range matched {
			names = append(names, a.Name)
		}
		warnMsg(fmt.Sprintf("Pattern matched %d interfaces: %s", len(matched), strings.Join(names, ", ")))
		warnMsg(fmt.Sprintf("Using first match: %s (use a more specific pattern or exact name)", matched[0].Name))
	}
	return matched[0].GUID, matched[0].Name, nil
}

// autoDetectInterface returns the friendly name of the first non-loopback
// adapter that has at least one DNS server configured — a sensible default
// when the user doesn't pass --interface.
func autoDetectInterface() (string, error) {
	adapters, err := getAdapters()
	if err != nil {
		return "", err
	}

	// Prefer adapters that are active (have DNS) and not loopback.
	// Priority: Wi-Fi > Ethernet > anything else.
	priority := func(name string) int {
		n := strings.ToLower(name)
		switch {
		case strings.HasPrefix(n, "wi-fi") || strings.HasPrefix(n, "wifi") || strings.HasPrefix(n, "wlan"):
			return 0
		case strings.HasPrefix(n, "ethernet"):
			return 1
		default:
			return 2
		}
	}

	type candidate struct {
		name     string
		priority int
	}
	var candidates []candidate
	for name, a := range adapters {
		if a.IsLoopback {
			continue
		}
		if len(a.IPv4DNS)+len(a.IPv6DNS) == 0 {
			continue
		}
		candidates = append(candidates, candidate{name, priority(name)})
	}
	if len(candidates) == 0 {
		// Fallback: any non-loopback adapter.
		for name, a := range adapters {
			if !a.IsLoopback {
				candidates = append(candidates, candidate{name, priority(name)})
			}
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no suitable network interface found — use --interface / -i to specify one")
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority < candidates[j].priority
		}
		return candidates[i].name < candidates[j].name
	})
	return candidates[0].name, nil
}

// ── Registry DNS read / write ────────────────────────────────────────────────

// splitDNS splits a Windows DNS string (space- or comma-separated).
func splitDNS(s string) []string {
	s = strings.ReplaceAll(s, ",", " ")
	return strings.Fields(s)
}

// getRegistryDNS returns static NameServer and DHCP DhcpNameServer for a GUID.
func getRegistryDNS(guid string) (static, dhcp []string, err error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		tcpipParamsPath+`\`+guid, registry.QUERY_VALUE)
	if err != nil {
		return nil, nil, err
	}
	defer key.Close()
	if v, _, e := key.GetStringValue("NameServer"); e == nil && v != "" {
		static = splitDNS(v)
	}
	if v, _, e := key.GetStringValue("DhcpNameServer"); e == nil && v != "" {
		dhcp = splitDNS(v)
	}
	return
}

// setRegistryDNS writes static DNS servers to the registry.
// Passing nil/empty clears the static entry (reverts to DHCP).
func setRegistryDNS(guid string, servers []string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		tcpipParamsPath+`\`+guid,
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key for %s: %w\n  (are you running as Administrator?)", guid, err)
	}
	defer key.Close()
	value := strings.Join(servers, ",")
	if err := key.SetStringValue("NameServer", value); err != nil {
		return fmt.Errorf("write NameServer: %w", err)
	}
	return nil
}

// ── DNS cache flush via DnsApi.dll ───────────────────────────────────────────

var (
	dnsapi                    = windows.NewLazyDLL("dnsapi.dll")
	procDnsFlushResolverCache = dnsapi.NewProc("DnsFlushResolverCache")
)

// flushResolverCache calls DnsFlushResolverCache() from dnsapi.dll directly.
func flushResolverCache() error {
	r1, _, err := procDnsFlushResolverCache.Call()
	if r1 == 0 {
		return fmt.Errorf("DnsFlushResolverCache: %w", err)
	}
	return nil
}

// ── Service Control Manager ──────────────────────────────────────────────────

// restartService stops then starts a Windows service via the SCM.
func restartService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM connect: %w\n  (are you running as Administrator?)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("open service %q: %w", name, err)
	}
	defer s.Close()

	// Stop — tolerate "not running".
	stepMsg("⏳", fmt.Sprintf("Stopping  %-14s ...", name))
	status, err := s.Control(svc.Stop)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		warnMsg(fmt.Sprintf("Could not stop %s: %v (continuing)", name, err))
	} else {
		deadline := time.Now().Add(6 * time.Second)
		for status.State != svc.Stopped && time.Now().Before(deadline) {
			time.Sleep(250 * time.Millisecond)
			status, _ = s.Query()
		}
		okMsg(fmt.Sprintf("Stopped   %s", name))
	}

	// Start.
	stepMsg("⏳", fmt.Sprintf("Starting  %-14s ...", name))
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service %q: %w", name, err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := s.Query()
		if st.State == svc.Running {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	okMsg(fmt.Sprintf("Started   %s", name))
	return nil
}

// ── Commands ─────────────────────────────────────────────────────────────────

func cmdListAdapters() error {
	sep()
	bold.Println("  Network Adapters")
	sep()

	adapters, err := getAdapters()
	if err != nil {
		return err
	}
	if len(adapters) == 0 {
		warnMsg("No network adapters found.")
		sep()
		return nil
	}

	names := make([]string, 0, len(adapters))
	for n := range adapters {
		names = append(names, n)
	}
	sort.Strings(names)

	const col = 32 // visual column width for adapter name column
	for _, name := range names {
		a := adapters[name]

		// Name + DHCP/Static badge on same line.
		cyan.Printf("  %-*s", col, name)
		if a.IsLoopback {
			dim.Printf("  Loopback\n")
		} else if a.DHCPEnabled {
			green.Printf("  DHCP\n")
		} else {
			yellow.Printf("  Static\n")
		}

		// Description indented under the name.
		dim.Printf("  %-*s  %s\n", col, "", a.Description)

		// Active DNS servers if any.
		allDNS := append(a.IPv4DNS, a.IPv6DNS...)
		if len(allDNS) > 0 {
			fmt.Printf("  %-*s  %s\n", col, "", strings.Join(allDNS, "  "))
		}
	}

	sep()
	dim.Println("  Use the interface name with --interface / -i (supports wildcards and regex).")
	sep()
	return nil
}

func colors(hex, text string) string {
	if hex == "" {
		return text
	}
	var r, g, b int
	fmt.Sscanf(hex, "#%02x%02x%02x", &r, &g, &b)
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", r, g, b, text)
}

func cmdShow(ifaceName string) error {
	sep()
	bold.Println("  Current DNS Configuration")
	sep()

	adapters, err := getAdapters()
	if err != nil {
		return err
	}

	var targets []*Adapter

	if ifaceName != "" {
		// Pattern given — resolve via exact / glob / regex.
		targets, err = matchAdapters(ifaceName, adapters)
		if err != nil {
			return err
		}
	} else {
		// No filter — show all non-loopback adapters that have any DNS.
		for _, a := range adapters {
			if !a.IsLoopback && (len(a.IPv4DNS)+len(a.IPv6DNS) > 0) {
				targets = append(targets, a)
			}
		}
		if len(targets) == 0 {
			warnMsg("No adapters with DNS servers found.")
			infoMsg("Run 'dnsman adapters' to list all interfaces.")
			sep()
			return nil
		}
	}

	sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })

	const col = 20
	for _, a := range targets {
		// cyan.Printf("  %-*s  %s\n", col, "Interface:", a.Name)
		fmt.Printf("  %-*s  %s\n", col, "Interface:", colors("#00FFFF", a.Name))
		// dim.Printf("  %-*s  %s\n", col, "Description:", a.Description)
		fmt.Printf("  %-*s  %s\n", col, "Description:", colors("#AAAAFF", a.Description))

		static, dhcp, _ := getRegistryDNS(a.GUID)

		if len(static) > 0 {
			green.Printf("  %-*s  %s\n", col, "Static DNS:", colors("#FFFF00", strings.Join(static, "  ")))
		} else {
			// dim.Printf("  %-*s  %s\n", col, "Static DNS:", "(none — using DHCP)")
			fmt.Printf("  %-*s  %s\n", col, "Static DNS:", colors("#FFAA7F", "DHCP"))
		}
		if len(dhcp) > 0 {
			dim.Printf("  %-*s  %s\n", col, "DHCP DNS:", colors("#FF557F", strings.Join(dhcp, "  ")))
		}
		if len(a.IPv4DNS) > 0 {
			fmt.Printf("  %-*s  %s\n", col, "Active IPv4 DNS:", colors("#0000FF", strings.Join(a.IPv4DNS, "  ")))
		}
		if len(a.IPv6DNS) > 0 {
			fmt.Printf("  %-*s  %s\n", col, "Active IPv6 DNS:", colors("#5500FF", strings.Join(a.IPv6DNS, "  ")))
		}
		dhcpStr := colors("#FF55FF", "No")
		if a.DHCPEnabled {
			dhcpStr = colors("#00AAFF", "Yes")
		}
		dim.Printf("  %-*s  %s\n", col, "DHCP Enabled:", dhcpStr)
		sep()
	}
	return nil
}

func cmdSet(ifaceName string, servers []string) error {
	if len(servers) == 0 {
		return fmt.Errorf("no DNS servers provided")
	}
	for _, s := range servers {
		if net.ParseIP(s) == nil {
			return fmt.Errorf("invalid IP address: %q", s)
		}
	}

	// Auto-detect interface if not specified.
	if ifaceName == "" {
		detected, err := autoDetectInterface()
		if err != nil {
			return err
		}
		ifaceName = detected
		infoMsg(fmt.Sprintf("Auto-detected interface: %s (use -i to override)", ifaceName))
	}

	guid, resolvedName, err := resolveGUID(ifaceName)
	if err != nil {
		return err
	}
	ifaceName = resolvedName // use the real adapter name in all output below

	sep()
	bold.Println("  Setting DNS Servers")
	sep()
	infoMsg(fmt.Sprintf("Interface : %s", ifaceName))
	infoMsg(fmt.Sprintf("GUID      : %s", guid))
	infoMsg(fmt.Sprintf("Servers   : %s", strings.Join(servers, "  ")))
	sep()

	stepMsg("⏳", "Writing DNS servers to Windows Registry...")
	if err := setRegistryDNS(guid, servers); err != nil {
		failMsg("Failed to write registry.")
		return err
	}
	okMsg("Registry updated.")

	stepMsg("⏳", "Flushing resolver cache (DnsFlushResolverCache)...")
	if err := flushResolverCache(); err != nil {
		warnMsg(fmt.Sprintf("Cache flush: %v", err))
	} else {
		okMsg("Resolver cache flushed.")
	}
	sep()
	return cmdShow(ifaceName)
}

func cmdFlush() error {
	sep()
	bold.Println("  Flushing DNS Resolver Cache")
	sep()
	stepMsg("⏳", "Calling DnsFlushResolverCache() ...")
	if err := flushResolverCache(); err != nil {
		failMsg(err.Error())
		return err
	}
	okMsg("DNS resolver cache flushed successfully.")
	sep()
	return nil
}

func cmdRestart(includeNamed bool) error {
	sep()
	bold.Println("  Restarting DNS Services")
	sep()

	services := []string{"dnscache"}
	if includeNamed {
		services = append(services, "named")
	}
	for _, svcName := range services {
		if err := restartService(svcName); err != nil {
			failMsg(fmt.Sprintf("%s: %v", svcName, err))
			return err
		}
		sep()
	}
	return cmdFlush()
}

func cmdReset(ifaceName string) error {
	// Auto-detect interface if not specified.
	if ifaceName == "" {
		detected, err := autoDetectInterface()
		if err != nil {
			return err
		}
		ifaceName = detected
		infoMsg(fmt.Sprintf("Auto-detected interface: %s (use -i to override)", ifaceName))
	}

	guid, resolvedName, err := resolveGUID(ifaceName)
	if err != nil {
		return err
	}
	ifaceName = resolvedName // use the real adapter name in all output below

	sep()
	bold.Println("  Resetting DNS to DHCP / Automatic")
	sep()
	infoMsg(fmt.Sprintf("Interface : %s", ifaceName))
	infoMsg(fmt.Sprintf("GUID      : %s", guid))

	stepMsg("⏳", "Clearing static NameServer in registry...")
	if err := setRegistryDNS(guid, nil); err != nil {
		failMsg("Failed to clear registry.")
		return err
	}
	okMsg("Static DNS cleared — interface will use DHCP-assigned servers.")

	stepMsg("⏳", "Flushing resolver cache...")
	if err := flushResolverCache(); err != nil {
		warnMsg(fmt.Sprintf("Cache flush: %v", err))
	} else {
		okMsg("Resolver cache flushed.")
	}
	sep()
	return cmdShow(ifaceName)
}

func cmdTest(host string) error {
	sep()
	bold.Println("  DNS Resolution Test")
	sep()
	infoMsg(fmt.Sprintf("Host: %s", host))
	sep()

	stepMsg("⏳", fmt.Sprintf("Resolving %s ...", host))
	start := time.Now()
	addrs, err := net.LookupHost(host)
	elapsed := time.Since(start)

	if err != nil {
		failMsg(fmt.Sprintf("Resolution failed: %v", err))
		return err
	}

	const col = 6
	for _, addr := range addrs {
		tag := "IPv4"
		if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
			tag = "IPv6"
		}
		green.Printf("  %-*s  %s\n", col, tag+":", addr)
	}
	sep()
	okMsg(fmt.Sprintf("Resolved %d address(es) in %dms", len(addrs), elapsed.Milliseconds()))

	// Reverse PTR on first result.
	if len(addrs) > 0 {
		stepMsg("⏳", fmt.Sprintf("Reverse lookup for %s ...", addrs[0]))
		if names, e := net.LookupAddr(addrs[0]); e == nil && len(names) > 0 {
			dim.Printf("  %-*s  %s\n", col, "PTR:", strings.Join(names, ", "))
		} else {
			dim.Printf("  %-*s  %s\n", col, "PTR:", "(no PTR record)")
		}
	}
	sep()
	return nil
}

func cmdListPresets() {
	sep()
	bold.Println("  Built-in DNS Presets")
	sep()
	names := make([]string, 0, len(dnsPresets))
	for n := range dnsPresets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		magenta.Printf("  %-16s", name)
		fmt.Printf("  %s\n", strings.Join(dnsPresets[name], ", "))
	}
	sep()
	dim.Println("  Usage: dnsman set --preset cloudflare")
	sep()
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	printBanner()

	var (
		ifaceName     string
		named         bool
		preset        string
		testHost      string
		extraFallback bool
	)

	root := &cobra.Command{
		Use:           "dnsman",
		Short:         "Windows DNS manager — no PowerShell, no net.exe, no ipconfig",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// ── adapters ─────────────────────────────────────────────────────────────
	adaptersCmd := &cobra.Command{
		Use:   "adapters",
		Short: "List all network adapters, DNS mode, and active DNS servers",
		RunE:  func(cmd *cobra.Command, args []string) error { return cmdListAdapters() },
	}

	// ── show ─────────────────────────────────────────────────────────────────
	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show DNS configuration (all active adapters, or one specific)",
		Example: `  dnsman show
  dnsman show -i "Wi-Fi"
  dnsman show -i "Ethernet"
  dnsman show -i "*VMnet*"
  dnsman show -i "Wi-Fi*"
  dnsman show -i "(?i)vmware.*vmnet[18]"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdShow(ifaceName)
		},
	}
	// Default is "" (empty) — means show all. User must pass -i for a specific one.
	showCmd.Flags().StringVarP(&ifaceName, "interface", "i", "", "Interface name, wildcard (*VMnet*), or regex (omit to show all)")

	// ── set ──────────────────────────────────────────────────────────────────
	setCmd := &cobra.Command{
		Use:   "set [ip1] [ip2] ...",
		Short: "Set static DNS servers for an interface (auto-detects if -i omitted)",
		Example: `  dnsman set 192.168.1.53
  dnsman set --preset cloudflare
  dnsman set 192.168.1.53 --preset google
  dnsman set 192.168.1.53 --fallback
  dnsman set --preset cloudflare -i "Ethernet"
  dnsman set --preset cloudflare -i "*VMnet8*"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			servers := append([]string{}, args...)
			if preset != "" {
				p, found := dnsPresets[strings.ToLower(preset)]
				if !found {
					return fmt.Errorf("unknown preset %q — run 'dnsman presets' to see options", preset)
				}
				servers = append(servers, p...)
			}
			if extraFallback {
				seen := map[string]bool{}
				for _, s := range servers {
					seen[s] = true
				}
				for _, fb := range []string{"1.1.1.1", "8.8.8.8", "8.8.4.4"} {
					if !seen[fb] {
						servers = append(servers, fb)
					}
				}
			}
			if len(servers) == 0 {
				return fmt.Errorf("provide at least one IP address or use --preset")
			}
			return cmdSet(ifaceName, servers)
		},
	}
	// Default "" so cmdSet can auto-detect.
	setCmd.Flags().StringVarP(&ifaceName, "interface", "i", "", "Interface name, wildcard (*VMnet*), or regex (auto-detected if omitted)")
	setCmd.Flags().StringVarP(&preset, "preset", "p", "", "Built-in DNS preset (cloudflare, google, quad9, …)")
	setCmd.Flags().BoolVarP(&extraFallback, "fallback", "f", false, "Append 1.1.1.1 / 8.8.8.8 / 8.8.4.4 as extra fallbacks")

	// ── flush ─────────────────────────────────────────────────────────────────
	flushCmd := &cobra.Command{
		Use:   "flush",
		Short: "Flush the DNS resolver cache (DnsFlushResolverCache via dnsapi.dll)",
		RunE:  func(cmd *cobra.Command, args []string) error { return cmdFlush() },
	}

	// ── restart ───────────────────────────────────────────────────────────────
	restartCmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart dnscache (and optionally named) via SCM, then flush cache",
		Example: `  dnsman restart
  dnsman restart --named`,
		RunE: func(cmd *cobra.Command, args []string) error { return cmdRestart(named) },
	}
	restartCmd.Flags().BoolVarP(&named, "named", "n", false, "Also restart the BIND named service")

	// ── reset ─────────────────────────────────────────────────────────────────
	resetCmd := &cobra.Command{
		Use:   "reset",
		Short: "Clear static DNS — revert interface to DHCP-assigned servers",
		Example: `  dnsman reset
  dnsman reset -i "Ethernet"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdReset(ifaceName)
		},
	}
	// Default "" so cmdReset can auto-detect.
	resetCmd.Flags().StringVarP(&ifaceName, "interface", "i", "", "Interface name, wildcard (*VMnet*), or regex (auto-detected if omitted)")

	// ── test ──────────────────────────────────────────────────────────────────
	testCmd := &cobra.Command{
		Use:   "test [hostname]",
		Short: "Resolve a hostname — shows IPs, timing, and PTR record",
		Example: `  dnsman test
  dnsman test google.com
  dnsman test --host github.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			host := testHost
			if len(args) > 0 {
				host = args[0]
			}
			return cmdTest(host)
		},
	}
	testCmd.Flags().StringVarP(&testHost, "host", "H", "example.com", "Hostname to resolve")

	// ── presets ───────────────────────────────────────────────────────────────
	presetsCmd := &cobra.Command{
		Use:   "presets",
		Short: "List all built-in DNS provider presets",
		Run:   func(cmd *cobra.Command, args []string) { cmdListPresets() },
	}

	// ── version ───────────────────────────────────────────────────────────────
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version, commit hash, and build date",
		Run: func(cmd *cobra.Command, args []string) {
			sep()
			bold.Printf("  dnsman   v%s\n", colors("#00FFFF", version))
			dim.Printf("  Commit   %s\n", commit)
			dim.Printf("  Built    %s\n", date)
			fmt.Printf("  Author   %s <%s>\n", colors("#FFFF00", author), colors("#AAAAFF", email))
			fmt.Printf("  %s\n", colors("#FFAA7F", homepage))
			sep()
		},
	}

	root.AddCommand(adaptersCmd, showCmd, setCmd, flushCmd, restartCmd, resetCmd, testCmd, presetsCmd, versionCmd)

	if err := root.Execute(); err != nil {
		failMsg(err.Error())
		os.Exit(1)
	}
}
