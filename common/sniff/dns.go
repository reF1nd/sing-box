package sniff

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/task"

	mDNS "github.com/miekg/dns"
)

func StreamDomainNameQuery(readCtx context.Context, reader io.Reader, sniffdata chan SniffData) {
	var length uint16
	data := SniffData{
		metadata: nil,
		err:      nil,
	}
	err := binary.Read(reader, binary.BigEndian, &length)
	if err != nil {
		data.err = err
		sniffdata <- data
		return
	}
	if length == 0 {
		data.err = os.ErrInvalid
		sniffdata <- data
		return
	}
	buffer := buf.NewSize(int(length))
	defer buffer.Release()

	readCtx, cancel := context.WithTimeout(readCtx, time.Millisecond*100)
	var readTask task.Group
	readTask.Append0(func(ctx context.Context) error {
		return common.Error(buffer.ReadFullFrom(reader, buffer.FreeLen()))
	})
	err = readTask.Run(readCtx)
	cancel()
	if err != nil {
		data.err = err
		sniffdata <- data
		return
	}
	DomainNameQuery(readCtx, buffer.Bytes(), sniffdata)
}

func DomainNameQuery(ctx context.Context, packet []byte, sniffdata chan SniffData) {
	var msg mDNS.Msg
	data := SniffData{
		metadata: nil,
		err:      nil,
	}
	defer func() {
		sniffdata <- data
	}()
	err := msg.Unpack(packet)
	if err != nil {
		data.err = err
		return
	}
	if len(msg.Question) == 0 || msg.Question[0].Qclass != mDNS.ClassINET || !M.IsDomainName(msg.Question[0].Name) {
		data.err = os.ErrInvalid
		return
	}
	data.metadata = &adapter.InboundContext{Protocol: C.ProtocolDNS}
}
