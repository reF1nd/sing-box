//go:build linux

package listener

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

type oobBatchTestHandler struct {
	batch  chan int
	single atomic.Bool
}

func (h *oobBatchTestHandler) NewPacket(*buf.Buffer, []byte, M.Socksaddr) {
	h.single.Store(true)
}

func (h *oobBatchTestHandler) NewOOBPacketBatch(buffers []*buf.Buffer, oobs [][]byte, sources []M.Socksaddr) {
	defer buf.ReleaseMulti(buffers)
	if len(buffers) != len(oobs) || len(buffers) != len(sources) {
		h.batch <- -1
		return
	}
	for _, oob := range oobs {
		if len(oob) == 0 {
			h.batch <- -1
			return
		}
	}
	h.batch <- len(buffers)
}

func TestListenerUsesOOBPacketBatchHandler(t *testing.T) {
	handler := &oobBatchTestHandler{batch: make(chan int, 8)}
	server := New(Options{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
		Network: []string{"udp"},
		Listen: option.ListenOptions{
			Listen: common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
		},
		OOBPacketHandler:    handler,
		DisablePacketOutput: true,
		DisableLog:          true,
		SocketControl: func(_ string, _ string, rawConn syscall.RawConn) error {
			return control.Raw(rawConn, func(fd uintptr) error {
				return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			})
		},
	})
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.UDPConn().LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for index := range 4 {
		if _, err = client.Write([]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case count := <-handler.batch:
		if count <= 0 {
			t.Fatal("listener delivered an invalid OOB batch")
		}
	case <-time.After(time.Second):
		t.Fatal("listener did not deliver an OOB batch")
	}
	if handler.single.Load() {
		t.Fatal("listener fell back to one-packet OOB handling")
	}
}
