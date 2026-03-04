package root

type RootSource string

const (
	SourceNginxRoot  RootSource = "nginx.root"
	SourceNginxAlias RootSource = "nginx.alias"
	SourceApacheDR   RootSource = "apache.documentroot"
	SourceManual     RootSource = "manual"
)

type RootEntry struct {
	Path        string     `json:"path"`
	RealPath    string     `json:"real_path,omitempty"`
	Source      RootSource `json:"source"`
	ContextHint string     `json:"context_hint,omitempty"`
}
