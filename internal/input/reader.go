package input

import (
	"io"
	"os"
)

func ReadAllMaybeStdin(pathOrDash string) ([]byte, error) {
	var r io.Reader
	if pathOrDash == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(pathOrDash)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	return io.ReadAll(r)
}
