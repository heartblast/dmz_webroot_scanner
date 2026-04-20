package rules

import (
	"strings"

	"github.com/heartblast/detect_bot/internal/model"
)

type AllowlistRule struct {
	AllowMimePrefixes []string
	AllowExt          map[string]bool
}

func (r *AllowlistRule) Name() string { return "allowlist" }

func (r *AllowlistRule) Evaluate(ctx model.FileCtx) []Reason {
	out := make([]Reason, 0, 2)

	if !mimeAllowed(ctx.Mime, r.AllowMimePrefixes) {
		out = append(out, Reason{
			Code:     "mime_not_in_allowlist",
			Severity: SevHigh,
			Message:  "MIME is not allowed by prefix allowlist",
		})
	}

	ext := policyExt(ctx)
	if ext != "" && !r.AllowExt[ext] {
		out = append(out, Reason{
			Code:     "ext_not_in_allowlist",
			Severity: SevHigh,
			Message:  "Extension is not allowed by allowlist",
		})
	}

	return out
}

func mimeAllowed(mime string, prefixes []string) bool {
	m := strings.ToLower(strings.TrimSpace(mime))
	for _, p := range prefixes {
		pp := strings.ToLower(strings.TrimSpace(p))
		if pp == "" {
			continue
		}
		if m == pp {
			return true
		}
		if strings.HasSuffix(pp, "/") && strings.HasPrefix(m, pp) {
			return true
		}
		if strings.HasSuffix(pp, "-") && strings.HasPrefix(m, pp) {
			return true
		}
	}
	return false
}
