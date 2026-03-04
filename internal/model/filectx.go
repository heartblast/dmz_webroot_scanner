package model

import (
	"time"

	"dmz_webroot_scanner/internal/root"
)

type FileCtx struct {
	Path       string
	RealPath   string
	RootPath   string
	RootSource root.RootSource

	Size    int64
	ModTime time.Time
	Perm    string
	Ext     string
	Mime    string
}
