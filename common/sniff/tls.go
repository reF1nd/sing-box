package sniff

import (
	"context"
	"crypto/tls"
	"io"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"
)

func tlsClientHello(ctx context.Context, reader io.Reader, data *SniffData) {
	var clientHello *tls.ClientHelloInfo
	err := tls.Server(bufio.NewReadOnlyConn(reader), &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHello = argHello
			return nil, nil
		},
	}).HandshakeContext(ctx)
	if clientHello != nil {
		data.metadata = &adapter.InboundContext{Protocol: C.ProtocolTLS, Domain: clientHello.ServerName}
		return
	}
	data.err = err
}

func TLSClientHello(ctx context.Context, reader io.Reader, sniffdata chan SniffData, wg *sync.WaitGroup) {
	var data SniffData
	tlsClientHello(ctx, reader, &data)
	sniffdata <- data
	wg.Done()
}
