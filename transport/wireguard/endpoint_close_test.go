//go:build with_gvisor

package wireguard

import (
	"encoding/base64"
	"errors"
	"net"
	"testing"
)

func TestEndpointCloseBeforeStart(t *testing.T) {
	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    t.Context(),
		PrivateKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := endpoint.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := endpoint.startDevice(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed error, got %v", err)
	}
}
