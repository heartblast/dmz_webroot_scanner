package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dmz_webroot_scanner/internal/config"
	"dmz_webroot_scanner/internal/model"
	"dmz_webroot_scanner/internal/report"
	"dmz_webroot_scanner/internal/root"
	"dmz_webroot_scanner/internal/rules"
)

type Scanner struct {
	Cfg   config.Config
	Rules []rules.Rule
}

func (s *Scanner) ScanRoots(roots []root.RootEntry) ([]report.Finding, int) {
	var scanned int64

	findCh := make(chan report.Finding, 256)
	pathCh := make(chan walkItem, 1024)

	workers := s.Cfg.Workers
	if workers <= 0 {
		workers = 1
	}

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for it := range pathCh {
				atomic.AddInt64(&scanned, 1)

				ctx, ok := s.buildFileCtx(it)
				if !ok {
					continue
				}

				reasons := s.evalRules(ctx)
				if len(reasons) == 0 {
					continue
				}

				f := report.Finding{
					Path:                 ctx.Path,
					RealPath:             ctx.RealPath,
					Size:                 ctx.Size,
					ModTime:              ctx.ModTime.Format(time.RFC3339),
					Perm:                 ctx.Perm,
					Ext:                  ctx.Ext,
					MimeSniff:            ctx.Mime,
					Reasons:              toCodes(reasons),
					Severity:             maxSeverity(reasons).String(),
					URLExposureHeuristic: "potentially_web_reachable",
					RootMatched:          ctx.RootPath,
					RootSource:           string(ctx.RootSource),
				}

				// Optional hash (bounded by max-size-mb)
				if s.Cfg.ComputeHash && ctx.Size <= s.Cfg.MaxSizeMB*1024*1024 {
					if h, err := sha256FileBounded(ctx.Path, s.Cfg.MaxSizeMB*1024*1024); err == nil {
						f.SHA256 = h
					}
				}

				findCh <- f
			}
		}()
	}

	// Producer: walk roots and enqueue file items
	go func() {
		defer close(pathCh)
		for _, r := range roots {
			walkRoot(r, s.Cfg, pathCh)
		}
	}()

	// Closer
	go func() {
		wg.Wait()
		close(findCh)
	}()

	findings := make([]report.Finding, 0, 128)
	for f := range findCh {
		findings = append(findings, f)
	}

	// Sort: more reasons first, then size desc, then path asc (기존 코드와 동일한 방향)
	sort.Slice(findings, func(i, j int) bool {
		if len(findings[i].Reasons) != len(findings[j].Reasons) {
			return len(findings[i].Reasons) > len(findings[j].Reasons)
		}
		if findings[i].Size != findings[j].Size {
			return findings[i].Size > findings[j].Size
		}
		return findings[i].Path < findings[j].Path
	})

	return findings, int(scanned)
}

func (s *Scanner) evalRules(ctx model.FileCtx) []rules.Reason {
	out := make([]rules.Reason, 0, 4)
	for _, r := range s.Rules {
		out = append(out, r.Evaluate(ctx)...)
	}
	return out
}

func toCodes(rs []rules.Reason) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Code)
	}
	return out
}

func maxSeverity(rs []rules.Reason) rules.Severity {
	max := rules.SevLow
	for _, r := range rs {
		if r.Severity > max {
			max = r.Severity
		}
	}
	return max
}

// buildFileCtx: stat/sniff/realpath 등 “파일 단위 컨텍스트” 구성
func (s *Scanner) buildFileCtx(it walkItem) (model.FileCtx, bool) {
	info := it.Info
	path := it.Path

	// newer-than filter
	if s.Cfg.NewerThanH > 0 {
		cut := time.Now().Add(-time.Duration(s.Cfg.NewerThanH) * time.Hour)
		if info.ModTime().Before(cut) {
			return model.FileCtx{}, false
		}
	}

	ext := strings.ToLower(filepath.Ext(path))
	perm := info.Mode().Perm().String()

	real := ""
	if rp, err := filepath.EvalSymlinks(path); err == nil {
		real = rp
	}

	// sniff mime (512B)
	mime := "unknown"
	if info.Size() == 0 {
		mime = "application/octet-stream"
	} else {
		if m, err := sniffMime(path, 512); err == nil && m != "" {
			mime = m
		}
	}

	return model.FileCtx{
		Path:       path,
		RealPath:   real,
		RootPath:   it.Root.Path,
		RootSource: it.Root.Source,
		Size:       info.Size(),
		ModTime:    info.ModTime(),
		Perm:       perm,
		Ext:        ext,
		Mime:       mime,
	}, true
}

func sha256FileBounded(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	var read int64
	buf := make([]byte, 64*1024)
	for {
		if maxBytes > 0 && read >= maxBytes {
			break
		}
		n, err := f.Read(buf)
		if n > 0 {
			toWrite := n
			if maxBytes > 0 && read+int64(n) > maxBytes {
				toWrite = int(maxBytes - read)
			}
			_, _ = h.Write(buf[:toWrite])
			read += int64(toWrite)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
