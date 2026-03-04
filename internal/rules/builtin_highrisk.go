package rules

import "dmz_webroot_scanner/internal/model"

type HighRiskExtRule struct {
	HighRisk map[string]bool
}

func (r *HighRiskExtRule) Name() string { return "high_risk_ext" }

func (r *HighRiskExtRule) Evaluate(ctx model.FileCtx) []Reason {
	if ctx.Ext != "" && r.HighRisk[ctx.Ext] {
		return []Reason{{
			Code:     "high_risk_extension",
			Severity: SevCritical,
			Message:  "High-risk extension detected in web-serving path",
		}}
	}
	return nil
}
