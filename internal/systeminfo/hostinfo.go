package systeminfo

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// HostInfo stores host identification metadata included in scan reports.
type HostInfo struct {
	Hostname    string   `json:"hostname"`
	IPAddresses []string `json:"ip_addresses"`
	PrimaryIP   string   `json:"primary_ip"`
	OSType      string   `json:"os_type"`
	OSName      string   `json:"os_name,omitempty"`
	OSVersion   string   `json:"os_version,omitempty"`
	Platform    string   `json:"platform,omitempty"`
	CollectedAt string   `json:"collected_at,omitempty"`
}

// GetHostInfo returns best-effort host metadata without failing the scan flow.
func GetHostInfo(now time.Time) HostInfo {
	info := HostInfo{
		Hostname:    "unknown",
		IPAddresses: []string{},
		OSType:      normalizeOSType(runtime.GOOS),
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		CollectedAt: now.Format(time.RFC3339),
	}

	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		info.Hostname = strings.TrimSpace(hostname)
	}

	info.IPAddresses, info.PrimaryIP = collectIPAddresses()
	info.OSName, info.OSVersion = collectOSDetails()
	return info
}

func normalizeOSType(goos string) string {
	switch strings.ToLower(strings.TrimSpace(goos)) {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin":
		return "darwin"
	default:
		return strings.ToLower(strings.TrimSpace(goos))
	}
}

func collectIPAddresses() ([]string, string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return []string{}, ""
	}

	privateIPv4 := []string{}
	otherIPv4 := []string{}
	ipv6 := []string{}
	seen := map[string]struct{}{}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ip := addrToNetIP(addr)
			if ip == nil || ip.IsLoopback() {
				continue
			}

			ipStr := ip.String()
			if _, exists := seen[ipStr]; exists {
				continue
			}
			seen[ipStr] = struct{}{}

			if ip4 := ip.To4(); ip4 != nil {
				ip4Str := ip4.String()
				if isPrivateIPv4(ip4) {
					privateIPv4 = append(privateIPv4, ip4Str)
				} else {
					otherIPv4 = append(otherIPv4, ip4Str)
				}
				continue
			}

			if parsed, err := netip.ParseAddr(ipStr); err == nil && !parsed.IsLinkLocalUnicast() {
				ipv6 = append(ipv6, parsed.String())
			}
		}
	}

	sort.Strings(privateIPv4)
	sort.Strings(otherIPv4)
	sort.Strings(ipv6)

	ordered := append([]string{}, privateIPv4...)
	ordered = append(ordered, otherIPv4...)
	ordered = append(ordered, ipv6...)

	primary := ""
	if len(ordered) > 0 {
		primary = ordered[0]
	}
	return ordered, primary
}

func addrToNetIP(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

func isPrivateIPv4(ip net.IP) bool {
	addr, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false
	}
	return addr.IsPrivate()
}

func collectOSDetails() (string, string) {
	switch runtime.GOOS {
	case "linux":
		return linuxDetails()
	case "darwin":
		return darwinDetails()
	default:
		return "", ""
	}
}

func linuxDetails() (string, string) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "", ""
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		values[key] = strings.Trim(value, `"'`)
	}

	name := firstNonEmpty(values["NAME"], values["PRETTY_NAME"])
	version := firstNonEmpty(values["VERSION_ID"], values["VERSION"])
	return name, version
}

func darwinDetails() (string, string) {
	const systemVersionPlist = "/System/Library/CoreServices/SystemVersion.plist"
	content, err := os.ReadFile(filepath.Clean(systemVersionPlist))
	if err != nil {
		return "macOS", ""
	}

	text := string(content)
	name := extractPlistString(text, "ProductName")
	version := extractPlistString(text, "ProductVersion")
	if name == "" {
		name = "macOS"
	}
	return name, version
}

func extractPlistString(content, key string) string {
	marker := "<key>" + key + "</key>"
	index := strings.Index(content, marker)
	if index < 0 {
		return ""
	}
	rest := content[index+len(marker):]
	start := strings.Index(rest, "<string>")
	end := strings.Index(rest, "</string>")
	if start < 0 || end < 0 || end <= start {
		return ""
	}
	return strings.TrimSpace(rest[start+len("<string>") : end])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
