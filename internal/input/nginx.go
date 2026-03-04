package input

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"dmz_webroot_scanner/internal/root"
)

func ParseNginxDump(b []byte) []root.RootEntry {
	sc := bufio.NewScanner(bytes.NewReader(b))
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 10*1024*1024)

	reRoot := regexp.MustCompile(`(?i)^\s*root\s+([^;#]+);`)
	reAlias := regexp.MustCompile(`(?i)^\s*alias\s+([^;#]+);`)
	reServerName := regexp.MustCompile(`(?i)^\s*server_name\s+([^;#]+);`)
	reConfFileLine := regexp.MustCompile(`(?i)^#\s*configuration\s+file\s+(.+?):(\d+)`)

	var lastServerName, lastFileLine string
	out := []root.RootEntry{}

	for sc.Scan() {
		line := sc.Text()

		if m := reConfFileLine.FindStringSubmatch(line); len(m) == 3 {
			lastFileLine = fmt.Sprintf("%s:%s", strings.TrimSpace(m[1]), m[2])
		}
		if m := reServerName.FindStringSubmatch(line); len(m) == 2 {
			lastServerName = strings.TrimSpace(m[1])
		}
		if m := reRoot.FindStringSubmatch(line); len(m) == 2 {
			out = append(out, root.RootEntry{
				Path:        strings.TrimSpace(m[1]),
				Source:      root.SourceNginxRoot,
				ContextHint: joinHint(lastFileLine, "server_name="+lastServerName),
			})
		}
		if m := reAlias.FindStringSubmatch(line); len(m) == 2 {
			out = append(out, root.RootEntry{
				Path:        strings.TrimSpace(m[1]),
				Source:      root.SourceNginxAlias,
				ContextHint: joinHint(lastFileLine, "server_name="+lastServerName),
			})
		}
	}
	return out
}

func joinHint(a, b string) string {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + " | " + b
}
