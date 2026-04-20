package scan

import "testing"

func TestEffectivePolicyExtForRotatedLogs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "plain log",
			path: "/var/log/app/access.log",
			want: ".log",
		},
		{
			name: "compact date rotated log",
			path: "/var/log/app/access.log.20260419",
			want: ".log",
		},
		{
			name: "dash date rotated log",
			path: "/var/log/app/error.log.2026-04-19",
			want: ".log",
		},
		{
			name: "unknown date suffix is not normalized",
			path: "/var/www/unknown.file.20260419",
			want: ".20260419",
		},
		{
			name: "non date log suffix is not normalized",
			path: "/var/log/app/access.log.old",
			want: ".old",
		},
		{
			name: "php date suffix is not normalized as log",
			path: "/var/www/shell.php.20260419",
			want: ".20260419",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := effectivePolicyExt(tt.path); got != tt.want {
				t.Fatalf("effectivePolicyExt(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
