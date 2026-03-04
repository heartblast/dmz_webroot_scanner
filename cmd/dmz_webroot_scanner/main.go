package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"dmz_webroot_scanner/internal/config"
	"dmz_webroot_scanner/internal/input"
	"dmz_webroot_scanner/internal/report"
	"dmz_webroot_scanner/internal/root"
	"dmz_webroot_scanner/internal/rules"
	"dmz_webroot_scanner/internal/scan"
)

func main() {
	cfg := config.MustParseFlags()

	rep := report.Report{
		ReportVersion: "1.0",
		GeneratedAt:   time.Now().Format(time.RFC3339),
		Inputs:        []string{},
	}

	host, _ := os.Hostname()
	rep.Host = host

	// 1) roots 수집
	roots := make([]root.RootEntry, 0, 32)

	if cfg.NginxDump != "" {
		rep.Inputs = append(rep.Inputs, "nginx-dump:"+cfg.NginxDump)
		b, err := input.ReadAllMaybeStdin(cfg.NginxDump)
		must(err, "read nginx dump")
		roots = append(roots, input.ParseNginxDump(b)...)
	}

	if cfg.ApacheDump != "" {
		rep.Inputs = append(rep.Inputs, "apache-dump:"+cfg.ApacheDump)
		b, err := input.ReadAllMaybeStdin(cfg.ApacheDump)
		must(err, "read apache dump")
		roots = append(roots, input.ParseApacheDump(b)...)
	}

	for _, d := range cfg.WatchDirs {
		roots = append(roots, root.RootEntry{
			Path:   d,
			Source: root.SourceManual,
		})
	}

	roots = root.NormalizeRoots(roots)
	rep.Roots = roots
	rep.Stats.RootsCount = len(roots)

	// 2) scan 안 하더라도 roots/inputs만 리포트로 남길 수 있음
	if cfg.Scan {
		// 룰셋 조립(기존 로직 기반)
		allowExt := map[string]bool{}
		for _, e := range cfg.AllowExt {
			allowExt[strings.ToLower(strings.TrimSpace(e))] = true
		}

		ruleSet := []rules.Rule{
			&rules.AllowlistRule{
				AllowMimePrefixes: lowerSlice(cfg.AllowMimePref),
				AllowExt:          allowExt,
			},
			&rules.HighRiskExtRule{HighRisk: defaultHighRiskExt()},
			&rules.LargeFileRule{ThresholdBytes: 50 * 1024 * 1024}, // 기존 50MB
			&rules.ExtMimeMismatchRule{},
		}

		sc := scan.Scanner{
			Cfg:   cfg,
			Rules: ruleSet,
		}

		findings, scanned := sc.ScanRoots(roots)
		rep.Findings = findings
		rep.Stats.ScannedFiles = scanned
		rep.Stats.FindingsCount = len(findings)
	}

	// 3) 출력
	must(report.Write(rep, cfg.Output), "write report")
}

func lowerSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}

func defaultHighRiskExt() map[string]bool {
	return map[string]bool{
		".zip": true, ".tar": true, ".tgz": true, ".gz": true, ".7z": true, ".rar": true,
		".sql": true, ".csv": true, ".xlsx": true, ".xls": true, ".jsonl": true,
		".php": true, ".phtml": true, ".phar": true, ".cgi": true, ".pl": true, ".py": true, ".rb": true,
		".jsp": true, ".jspx": true, ".asp": true, ".aspx": true,
		".exe": true, ".dll": true, ".so": true, ".bin": true, ".sh": true,
	}
}

func must(err error, msg string) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", msg, err)
	os.Exit(1)
}
