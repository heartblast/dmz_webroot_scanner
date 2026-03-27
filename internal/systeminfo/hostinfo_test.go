package systeminfo

import (
	"runtime"
	"testing"
	"time"
)

func TestGetHostInfoProvidesRequiredFields(t *testing.T) {
	info := GetHostInfo(time.Date(2026, 3, 27, 9, 0, 0, 0, time.FixedZone("KST", 9*60*60)))

	if info.Hostname == "" {
		t.Fatalf("expected hostname to be populated")
	}
	if info.OSType == "" {
		t.Fatalf("expected os_type to be populated")
	}
	if info.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("unexpected platform: %q", info.Platform)
	}
	if info.CollectedAt == "" {
		t.Fatalf("expected collected_at to be populated")
	}
	if info.IPAddresses == nil {
		t.Fatalf("expected ip_addresses to be a non-nil slice")
	}
	if len(info.IPAddresses) == 0 && info.PrimaryIP != "" {
		t.Fatalf("expected empty primary_ip when there are no addresses")
	}
	if len(info.IPAddresses) > 0 && info.PrimaryIP == "" {
		t.Fatalf("expected primary_ip when addresses are present")
	}
}

func TestNormalizeOSType(t *testing.T) {
	tests := map[string]string{
		"windows": "windows",
		"linux":   "linux",
		"darwin":  "darwin",
		"freebsd": "freebsd",
		" Linux ": "linux",
	}

	for input, want := range tests {
		if got := normalizeOSType(input); got != want {
			t.Fatalf("normalizeOSType(%q) = %q, want %q", input, got, want)
		}
	}
}
