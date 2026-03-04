package report

import (
	"encoding/json"
	"io"
	"os"
)

func Write(rep Report, out string) error {
	var w io.Writer
	if out == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
