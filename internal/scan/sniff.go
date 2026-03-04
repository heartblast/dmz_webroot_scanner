package scan

import (
	"errors"
	"io"
	"net/http"
	"os"
)

func sniffMime(path string, max int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, max)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		if n == 0 {
			return "", err
		}
	}
	return http.DetectContentType(buf[:n]), nil
}
