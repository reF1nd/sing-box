package script

import "strings"

type logWriter struct {
	prefix  string
	logFunc func(...any)
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	s := string(p)
	s = strings.TrimRight(s, "\r\n")
	w.logFunc(w.prefix+": ", s)
	return len(p), nil
}
