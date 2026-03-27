package consolelog

import (
	"fmt"
	"io"
	"os"
)

// Logger writes short human-readable execution logs for CLI runs.
type Logger struct {
	infoWriter  io.Writer
	warnWriter  io.Writer
	errorWriter io.Writer
}

// New returns a logger that keeps JSON stdout clean when requested.
func New(outputToStdout bool) Logger {
	infoWriter := io.Writer(os.Stdout)
	if outputToStdout {
		infoWriter = os.Stderr
	}
	return Logger{
		infoWriter:  infoWriter,
		warnWriter:  os.Stderr,
		errorWriter: os.Stderr,
	}
}

func (l Logger) Infof(format string, args ...interface{}) {
	logf(l.infoWriter, "INFO", format, args...)
}

func (l Logger) Warnf(format string, args ...interface{}) {
	logf(l.warnWriter, "WARN", format, args...)
}

func (l Logger) Errorf(format string, args ...interface{}) {
	logf(l.errorWriter, "ERROR", format, args...)
}

func (l Logger) Summaryf(format string, args ...interface{}) {
	logf(l.infoWriter, "SUMMARY", format, args...)
}

func logf(w io.Writer, level string, format string, args ...interface{}) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "[%s] %s\n", level, fmt.Sprintf(format, args...))
}
