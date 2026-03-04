package report

import "dmz_webroot_scanner/internal/root"

type Finding struct {
	Path                 string   `json:"path"`
	RealPath             string   `json:"real_path,omitempty"`
	Size                 int64    `json:"size_bytes"`
	ModTime              string   `json:"mod_time"`
	Perm                 string   `json:"perm"`
	Ext                  string   `json:"ext"`
	MimeSniff            string   `json:"mime_sniff"`
	Reasons              []string `json:"reasons"`
	SHA256               string   `json:"sha256,omitempty"`
	URLExposureHeuristic string   `json:"url_exposure_heuristic,omitempty"`
	RootMatched          string   `json:"root_matched,omitempty"`
	RootSource           string   `json:"root_source,omitempty"`
	Severity             string   `json:"severity,omitempty"` // 추가(룰 엔진에서 계산)
}

type Report struct {
	ReportVersion string           `json:"report_version,omitempty"` // 추가(권장)
	GeneratedAt   string           `json:"generated_at"`
	Host          string           `json:"host,omitempty"`
	Inputs        []string         `json:"inputs"`
	Roots         []root.RootEntry `json:"roots"`
	Findings      []Finding        `json:"findings"`
	Stats         struct {
		RootsCount    int `json:"roots_count"`
		ScannedFiles  int `json:"scanned_files"`
		FindingsCount int `json:"findings_count"`
	} `json:"stats"`
}
