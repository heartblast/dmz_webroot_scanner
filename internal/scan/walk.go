package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"dmz_webroot_scanner/internal/config"
	"dmz_webroot_scanner/internal/root"
)

type walkItem struct {
	Path string
	Info fs.FileInfo
	Root root.RootEntry
}

func walkRoot(r root.RootEntry, cfg config.Config, out chan<- walkItem) {
	rootPath := r.Path
	if rootPath == "" {
		return
	}
	if _, err := os.Stat(rootPath); err != nil {
		return
	}

	exclude := normalizePrefixes(cfg.Exclude)

	_ = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// exclude
		if isExcluded(path, exclude) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// depth
		if cfg.MaxDepth > 0 && depth(rootPath, path) > cfg.MaxDepth {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// symlink policy
		if !cfg.FollowSymlink && d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}

		out <- walkItem{Path: path, Info: info, Root: r}
		return nil
	})
}

func normalizePrefixes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, filepath.Clean(p))
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

func isExcluded(path string, prefixes []string) bool {
	p := filepath.Clean(path)
	for _, pref := range prefixes {
		if p == pref {
			return true
		}
		if strings.HasPrefix(p, pref+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func depth(root, path string) int {
	r := filepath.Clean(root)
	p := filepath.Clean(path)
	if r == p {
		return 0
	}
	rel, err := filepath.Rel(r, p)
	if err != nil || rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(os.PathSeparator)))
}
