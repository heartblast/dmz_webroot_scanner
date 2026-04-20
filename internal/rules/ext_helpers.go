package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/heartblast/detect_bot/internal/model"
)

var dateSuffixRE = regexp.MustCompile(`^\.(?:\d{8}|\d{4}-\d{2}-\d{2})$`)

func policyExt(ctx model.FileCtx) string {
	if ctx.PolicyExt != "" {
		return strings.ToLower(ctx.PolicyExt)
	}
	return strings.ToLower(ctx.Ext)
}

func dateSuffixPreviousExt(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if !dateSuffixRE.MatchString(ext) {
		return ""
	}
	stem := strings.TrimSuffix(path, filepath.Ext(path))
	return strings.ToLower(filepath.Ext(stem))
}
