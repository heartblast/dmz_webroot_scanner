package rules

import "dmz_webroot_scanner/internal/model"

type Severity int

const (
	SevLow Severity = iota
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "critical"
	case SevHigh:
		return "high"
	case SevMedium:
		return "medium"
	default:
		return "low"
	}
}

type Reason struct {
	Code     string
	Severity Severity
	Message  string
}

type Rule interface {
	Name() string
	Evaluate(ctx model.FileCtx) []Reason
}
