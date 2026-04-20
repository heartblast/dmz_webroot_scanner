package rules

import (
	"testing"

	"github.com/heartblast/detect_bot/internal/model"
)

func TestAllowlistUsesPolicyExtForRotatedLog(t *testing.T) {
	t.Parallel()

	rule := &AllowlistRule{
		AllowMimePrefixes: []string{"text/plain"},
		AllowExt:          map[string]bool{".log": true},
	}
	ctx := model.FileCtx{
		Path:      "/var/log/app/access.log.20260419",
		Ext:       ".20260419",
		PolicyExt: ".log",
		Mime:      "text/plain",
	}

	if reasons := rule.Evaluate(ctx); len(reasons) != 0 {
		t.Fatalf("rotated log should be allowed, got reasons: %+v", reasons)
	}
}

func TestAllowlistDoesNotAllowUnknownDateSuffix(t *testing.T) {
	t.Parallel()

	rule := &AllowlistRule{
		AllowMimePrefixes: []string{"text/plain"},
		AllowExt:          map[string]bool{".log": true},
	}
	ctx := model.FileCtx{
		Path:      "/var/www/unknown.file.20260419",
		Ext:       ".20260419",
		PolicyExt: ".20260419",
		Mime:      "text/plain",
	}

	reasons := rule.Evaluate(ctx)
	if !hasReason(reasons, "ext_not_in_allowlist") {
		t.Fatalf("unknown date suffix should not be allowed, got reasons: %+v", reasons)
	}
}

func TestHighRiskDateSuffixBypassIsDetected(t *testing.T) {
	t.Parallel()

	rule := &HighRiskExtRule{HighRisk: map[string]bool{
		".php": true,
		".jsp": true,
	}}

	tests := []model.FileCtx{
		{Path: "/var/www/shell.php.20260419", Ext: ".20260419", PolicyExt: ".20260419"},
		{Path: "/var/www/payload.jsp.20260419", Ext: ".20260419", PolicyExt: ".20260419"},
	}

	for _, ctx := range tests {
		ctx := ctx
		t.Run(ctx.Path, func(t *testing.T) {
			t.Parallel()
			reasons := rule.Evaluate(ctx)
			if !hasReason(reasons, "high_risk_extension") {
				t.Fatalf("high-risk date suffix bypass should be detected, got reasons: %+v", reasons)
			}
		})
	}
}

func hasReason(reasons []Reason, code string) bool {
	for _, reason := range reasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}
