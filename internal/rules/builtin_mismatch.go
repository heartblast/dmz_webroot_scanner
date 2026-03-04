package rules

import (
	"strings"

	"dmz_webroot_scanner/internal/model"
)

type ExtMimeMismatchRule struct{}

func (r *ExtMimeMismatchRule) Name() string { return "ext_mime_mismatch" }

func (r *ExtMimeMismatchRule) Evaluate(ctx model.FileCtx) []Reason {
	var out []Reason
	m := strings.ToLower(ctx.Mime)

	// 이미지 확장자인데 MIME이 image/* 가 아니면 위장 가능성
	if isImageExt(ctx.Ext) && !strings.HasPrefix(m, "image/") {
		out = append(out, Reason{
			Code:     "ext_mime_mismatch_image",
			Severity: SevHigh,
			Message:  "Image extension but MIME is not image/*",
		})
	}

	// js/css/html인데 zip으로 탐지되면 위장/오탐 가능성
	if (ctx.Ext == ".js" || ctx.Ext == ".css" || ctx.Ext == ".html") && strings.HasPrefix(m, "application/zip") {
		out = append(out, Reason{
			Code:     "ext_mime_mismatch_archive",
			Severity: SevHigh,
			Message:  "Text/asset extension but MIME detected as archive",
		})
	}

	return out
}

func isImageExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico":
		return true
	default:
		return false
	}
}
