package config

import (
	"flag"
	"os"
	"strings"
)

type MultiFlag []string

func (m *MultiFlag) String() string { return strings.Join(*m, ",") }
func (m *MultiFlag) Set(s string) error {
	if s == "" {
		return nil
	}
	*m = append(*m, s)
	return nil
}

type Config struct {
	NginxDump     string
	ApacheDump    string
	Scan          bool
	Output        string
	MaxDepth      int
	MaxSizeMB     int64
	NewerThanH    int
	Exclude       MultiFlag
	AllowMimePref MultiFlag
	AllowExt      MultiFlag
	WatchDirs     MultiFlag
	ComputeHash   bool
	FollowSymlink bool

	// 성능/구조개선용 추가 옵션(선택)
	Workers int
}

func MustParseFlags() Config {
	var cfg Config
	flag.StringVar(&cfg.NginxDump, "nginx-dump", "", "path to nginx -T dump output file, or '-' for stdin")
	flag.StringVar(&cfg.ApacheDump, "apache-dump", "", "path to apachectl -S dump output file, or '-' for stdin")
	flag.BoolVar(&cfg.Scan, "scan", false, "scan discovered roots for suspicious files")
	flag.StringVar(&cfg.Output, "out", "report.json", "output JSON report path ('-' for stdout)")
	flag.IntVar(&cfg.MaxDepth, "max-depth", 12, "max directory recursion depth")
	flag.Int64Var(&cfg.MaxSizeMB, "max-size-mb", 100, "max file size (MB) to read for MIME sniff/hash")
	flag.IntVar(&cfg.NewerThanH, "newer-than-h", 0, "only flag files modified within last N hours (0=disable)")
	flag.Var(&cfg.Exclude, "exclude", "exclude path prefix (repeatable)")
	flag.Var(&cfg.AllowMimePref, "allow-mime-prefix", "allowed MIME prefixes (repeatable)")
	flag.Var(&cfg.AllowExt, "allow-ext", "allowed extensions (repeatable)")
	flag.Var(&cfg.WatchDirs, "watch-dir", "manual watch directory to include (repeatable)")
	flag.BoolVar(&cfg.ComputeHash, "hash", false, "compute SHA256 for findings")
	flag.BoolVar(&cfg.FollowSymlink, "follow-symlink", false, "follow symlinks (not recommended)")
	flag.IntVar(&cfg.Workers, "workers", 4, "number of scan workers (default 4)")
	flag.Parse()

	// Defaults (기존 코드와 동일)
	if len(cfg.AllowMimePref) == 0 {
		cfg.AllowMimePref = []string{
			"text/html", "text/css", "application/javascript", "text/javascript", "application/json",
			"image/", "font/", "application/font-",
			"application/xml", "text/plain",
		}
	}
	if len(cfg.AllowExt) == 0 {
		cfg.AllowExt = []string{
			".html", ".htm", ".css", ".js", ".mjs", ".json", ".xml", ".txt",
			".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
			".woff", ".woff2", ".ttf", ".otf", ".eot",
		}
	}

	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}

	// 최소 입력 검증은 main에서 “scan 여부” 고려해 처리해도 됨
	_ = os.Getenv // keep imports sane if needed later
	return cfg
}
