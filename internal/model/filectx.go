package model

import (
	"time"

	"github.com/heartblast/detect_bot/internal/root"
)

// FileCtx stores file metadata collected during scanning.
type FileCtx struct {
	Path       string
	RealPath   string
	RootPath   string
	RootSource root.RootSource

	Size      int64
	ModTime   time.Time
	Perm      string
	Ext       string // Actual last extension from the filename.
	PolicyExt string // Normalized extension used by policy/rule checks.
	Mime      string

	ContentSample      string
	ContentSampleBytes int
	ContentTruncated   bool
}
