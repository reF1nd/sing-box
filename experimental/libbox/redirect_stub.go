//go:build !linux

package libbox

import "os"

func NewAutoRedirectService(options []byte, handler AutoRedirectHandler) (AutoRedirectSession, error) {
	return nil, os.ErrInvalid
}

func NewAutoRedirectListener(inet6 bool, socketContext string) (int32, error) {
	return -1, os.ErrInvalid
}
