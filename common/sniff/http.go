package sniff

import (
	std_bufio "bufio"
	"context"
	"io"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/http"
)

func HTTPHost(ctx context.Context, reader io.Reader, sniffdata chan SniffData, wg *sync.WaitGroup) {
	var data SniffData
	defer func() {
		sniffdata <- data
		wg.Done()
	}()
	request, err := http.ReadRequest(std_bufio.NewReader(reader))
	if err != nil {
		data.err = err
		return
	}
	data.metadata = &adapter.InboundContext{Protocol: C.ProtocolHTTP, Domain: M.ParseSocksaddr(request.Host).AddrString()}
}
