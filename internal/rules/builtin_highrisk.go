package rules

import "github.com/heartblast/detect_bot/internal/model"

type HighRiskExtRule struct {
	HighRisk map[string]bool
}

func (r *HighRiskExtRule) Name() string { return "high_risk_ext" }

func (r *HighRiskExtRule) Evaluate(ctx model.FileCtx) []Reason {
	if r.highRiskExt(ctx) {
		return []Reason{{
			Code:     "high_risk_extension",
			Severity: SevCritical,
			Message:  "High-risk extension detected in web-serving path",
		}}
	}
	return nil
}

func (r *HighRiskExtRule) highRiskExt(ctx model.FileCtx) bool {
	if ext := policyExt(ctx); ext != "" && r.HighRisk[ext] {
		return true
	}
	if ext := dateSuffixPreviousExt(ctx.Path); ext != "" && r.HighRisk[ext] {
		return true
	}
	return false
}
