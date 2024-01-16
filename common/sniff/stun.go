package sniff

import (
	"context"
	"encoding/binary"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

func STUNMessage(ctx context.Context, packet []byte, sniffdata chan SniffData) {
	pLen := len(packet)
	data := SniffData{
		metadata: nil,
		err:      nil,
	}
	defer func() {
		sniffdata <- data
	}()
	if pLen < 20 {
		data.err = os.ErrInvalid
		return
	}
	if binary.BigEndian.Uint32(packet[4:8]) != 0x2112A442 {
		data.err = os.ErrInvalid
		return
	}
	if len(packet) < 20+int(binary.BigEndian.Uint16(packet[2:4])) {
		data.err = os.ErrInvalid
		return
	}
	data.metadata = &adapter.InboundContext{Protocol: C.ProtocolSTUN}
}
