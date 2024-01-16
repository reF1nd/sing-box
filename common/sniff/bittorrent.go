package sniff

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

func BittorrentTCPMessage(ctx context.Context, reader io.Reader, sniffdata chan SniffData) {
	data := SniffData{
		metadata: nil,
		err:      nil,
	}
	defer func() {
		sniffdata <- data
	}()

	packet, err := io.ReadAll(reader)
	if err != nil {
		data.err = os.ErrInvalid
		return
	}
	if len(packet) < 20 {
		data.err = os.ErrInvalid
		return
	}
	if packet[0] != 19 || string(packet[1:20]) != "BitTorrent protocol" {
		data.err = os.ErrInvalid
		return
	}
	data.metadata = &adapter.InboundContext{Protocol: C.ProtocolBittorrent}
}

func BittorrentUDPMessage(ctx context.Context, packet []byte, sniffdata chan SniffData) {
	data := SniffData{
		metadata: nil,
		err:      nil,
	}
	defer func() {
		sniffdata <- data
	}()

	pLen := len(packet)
	if pLen < 20 {
		data.err = os.ErrInvalid
		return
	}

	buffer := bytes.NewReader(packet)

	var typeAndVersion uint8

	if binary.Read(buffer, binary.BigEndian, &typeAndVersion) != nil {
		data.err = os.ErrInvalid
		return
	} else if packet[0]>>4&0xF > 4 || packet[0]&0xF != 1 {
		data.err = os.ErrInvalid
		return
	}

	var extension uint8

	if binary.Read(buffer, binary.BigEndian, &extension) != nil {
		data.err = os.ErrInvalid
		return
	} else if extension != 0 && extension != 1 {
		data.err = os.ErrInvalid
		return
	}

	for extension != 0 {
		if extension != 1 {
			data.err = os.ErrInvalid
			return
		}
		if binary.Read(buffer, binary.BigEndian, &extension) != nil {
			data.err = os.ErrInvalid
			return
		}

		var length uint8

		if err := binary.Read(buffer, binary.BigEndian, &length); err != nil {
			data.err = os.ErrInvalid
			return
		}
		if int32(pLen) >= int32(length) {
			data.err = os.ErrInvalid
			return
		}
	}

	if int32(pLen) >= int32(2) {
		data.err = os.ErrInvalid
		return
	}

	var timestamp uint32

	if err := binary.Read(buffer, binary.BigEndian, &timestamp); err != nil {
		data.err = os.ErrInvalid
		return
	}
	if math.Abs(float64(time.Now().UnixMicro()-int64(timestamp))) > float64(24*time.Hour) {
		data.err = os.ErrInvalid
		return
	}
	data.metadata = &adapter.InboundContext{Protocol: C.ProtocolBittorrent}
}
