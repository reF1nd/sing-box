package sniff

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

const (
	trackerConnectFlag = iota
	trackerAnnounceFlag
	trackerScrapeFlag

	trackerProtocolID = 0x41727101980

	trackerConnectMinSize  = 16
	trackerAnnounceMinSize = 20
	trackerScrapeMinSize   = 8
)

// BitTorrent detects if the stream is a BitTorrent connection.
// For the BitTorrent protocol specification, see https://www.bittorrent.org/beps/bep_0003.html
func BitTorrent(_ context.Context, reader io.Reader, sniffdata chan SniffData, wg *sync.WaitGroup) {
	var data SniffData
	defer func() {
		sniffdata <- data
		wg.Done()
	}()

	var first byte
	err := binary.Read(reader, binary.BigEndian, &first)
	if err != nil {
		data.err = err
		return
	}

	if first != 19 {
		data.err = os.ErrInvalid
		return
	}

	var protocol [19]byte
	_, err = reader.Read(protocol[:])
	if err != nil {
		data.err = err
		return
	}
	if string(protocol[:]) != "BitTorrent protocol" {
		data.err = os.ErrInvalid
		return
	}

	data.metadata = &adapter.InboundContext{Protocol: C.ProtocolBitTorrent}
}

// UTP detects if the packet is a uTP connection packet.
// For the uTP protocol specification, see
//  1. https://www.bittorrent.org/beps/bep_0029.html
//  2. https://github.com/bittorrent/libutp/blob/2b364cbb0650bdab64a5de2abb4518f9f228ec44/utp_internal.cpp#L112
func UTP(_ context.Context, packet []byte, sniffdata chan SniffData, wg *sync.WaitGroup) {
	var data SniffData
	defer func() {
		sniffdata <- data
		wg.Done()
	}()

	// A valid uTP packet must be at least 20 bytes long.
	if len(packet) < 20 {
		data.err = os.ErrInvalid
		return
	}

	version := packet[0] & 0x0F
	ty := packet[0] >> 4
	if version != 1 || ty > 4 {
		data.err = os.ErrInvalid
		return
	}

	// Validate the extensions
	extension := packet[1]
	reader := bytes.NewReader(packet[20:])
	for extension != 0 {
		err := binary.Read(reader, binary.BigEndian, &extension)
		if err != nil {
			data.err = err
			return
		}

		var length byte
		err = binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			data.err = err
			return
		}
		_, err = reader.Seek(int64(length), io.SeekCurrent)
		if err != nil {
			data.err = err
			return
		}
	}

	data.metadata = &adapter.InboundContext{Protocol: C.ProtocolBitTorrent}
}

// UDPTracker detects if the packet is a UDP Tracker Protocol packet.
// For the UDP Tracker Protocol specification, see https://www.bittorrent.org/beps/bep_0015.html
func UDPTracker(_ context.Context, packet []byte, sniffdata chan SniffData, wg *sync.WaitGroup) {
	var data SniffData
	defer func() {
		sniffdata <- data
		wg.Done()
	}()

	switch {
	case len(packet) >= trackerConnectMinSize &&
		binary.BigEndian.Uint64(packet[:8]) == trackerProtocolID &&
		binary.BigEndian.Uint32(packet[8:12]) == trackerConnectFlag:
		fallthrough
	case len(packet) >= trackerAnnounceMinSize &&
		binary.BigEndian.Uint32(packet[8:12]) == trackerAnnounceFlag:
		fallthrough
	case len(packet) >= trackerScrapeMinSize &&
		binary.BigEndian.Uint32(packet[8:12]) == trackerScrapeFlag:
		data.metadata = &adapter.InboundContext{Protocol: C.ProtocolBitTorrent}
		return
	default:
		data.err = os.ErrInvalid
		return
	}
}
