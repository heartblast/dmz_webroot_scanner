package rules

import "dmz_webroot_scanner/internal/model"

type LargeFileRule struct {
	ThresholdBytes int64
}

func (r *LargeFileRule) Name() string { return "large_file" }

func (r *LargeFileRule) Evaluate(ctx model.FileCtx) []Reason {
	if r.ThresholdBytes > 0 && ctx.Size >= r.ThresholdBytes {
		return []Reason{{
			Code:     "large_file_in_web_path",
			Severity: SevHigh,
			Message:  "Large file found under web-serving path (staging heuristic)",
		}}
	}
	return nil
}
