//go:build with_script

package script

import "strings"

type logWriter struct {
	f func(...any)
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	str := strings.TrimSpace(string(p))
	if str != "" {
		w.f(str)
	}
	return len(p), nil
}
