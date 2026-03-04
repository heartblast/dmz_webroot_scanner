package root

import (
	"path/filepath"
	"sort"
	"strings"
)

func NormalizeRoots(in []RootEntry) []RootEntry {
	seen := map[string]RootEntry{}
	for _, r := range in {
		p := strings.TrimSpace(r.Path)
		if p == "" {
			continue
		}
		p = strings.TrimRight(p, ";")
		p = strings.Trim(p, `"'`)
		p = filepath.Clean(p)

		real := ""
		if rp, err := filepath.EvalSymlinks(p); err == nil {
			real = rp
		}
		key := p
		if real != "" {
			key = real
		}

		if existing, ok := seen[key]; ok {
			if existing.ContextHint == "" && r.ContextHint != "" {
				existing.ContextHint = r.ContextHint
				seen[key] = existing
			}
			continue
		}
		r.Path = p
		r.RealPath = real
		seen[key] = r
	}

	out := make([]RootEntry, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
