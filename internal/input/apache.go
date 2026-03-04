package input

import (
	"regexp"
	"strings"

	"dmz_webroot_scanner/internal/root"
)

func ParseApacheDump(b []byte) []root.RootEntry {
	s := string(b)
	reDR := regexp.MustCompile(`(?i)\bDocumentRoot\s+"?([^"\r\n]+)"?`)

	out := []root.RootEntry{}
	for _, m := range reDR.FindAllStringSubmatch(s, -1) {
		if len(m) == 2 {
			out = append(out, root.RootEntry{
				Path:        strings.TrimSpace(m[1]),
				Source:      root.SourceApacheDR,
				ContextHint: "from apachectl -S dump",
			})
		}
	}
	return out
}
