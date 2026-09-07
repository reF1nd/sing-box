package v2rayhttp

import (
	"github.com/sagernet/sing/common/baderror"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http2"
)

// WrapHTTP2Error converts HTTP/2 stream failures into transport errors.
func WrapHTTP2Error(err error) error {
	err = baderror.WrapH2(err)
	if _, ok := err.(http2.StreamError); ok {
		// A nested HTTP/2 client must not mistake an underlying stream failure
		// for one of its own recoverable stream errors and retry reading forever.
		return E.Cause(err, "http2 transport")
	}
	return err
}
