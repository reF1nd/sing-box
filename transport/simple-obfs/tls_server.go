package obfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"

	B "github.com/sagernet/sing/common/buf"
)

type TLSObfsServer struct {
	net.Conn
	remain            int
	firstRequest      bool
	sessionTicketDone bool
	firstResponse     bool
}

func (c *TLSObfsServer) read(p []byte, discardLen int) (int, error) {
	discard := B.Get(discardLen)
	_, err := io.ReadFull(c.Conn, discard)
	B.Put(discard)
	if err != nil {
		return 0, err
	}
	var lengthBytes [2]byte
	if _, err = io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length > len(p) {
		n, readErr := c.Conn.Read(p)
		c.remain = length - n
		return n, readErr
	}
	return io.ReadFull(c.Conn, p[:length])
}

func (c *TLSObfsServer) Read(p []byte) (int, error) {
	if c.remain > 0 {
		length := min(c.remain, len(p))
		n, err := io.ReadFull(c.Conn, p[:length])
		c.remain -= n
		return n, err
	}
	if c.firstRequest {
		c.firstRequest = false
		return c.read(p, 9*16-4)
	}
	if !c.sessionTicketDone {
		c.sessionTicketDone = true
		buffer := make([]byte, 256)
		if _, err := c.read(buffer, 7); err != nil {
			return 0, err
		}
		if _, err := io.ReadFull(c.Conn, buffer[:4*16+2]); err != nil {
			return 0, err
		}
	}
	return c.read(p, 3)
}

func (c *TLSObfsServer) Write(p []byte) (int, error) {
	for offset := 0; offset < len(p); offset += chunkSize {
		end := min(offset+chunkSize, len(p))
		if _, err := c.write(p[offset:end]); err != nil {
			return offset, err
		}
	}
	return len(p), nil
}

func (c *TLSObfsServer) write(p []byte) (int, error) {
	if c.firstResponse {
		_, err := c.Conn.Write(makeTLSServerHello(p))
		c.firstResponse = false
		return len(p), err
	}
	buffer := B.NewSize(5 + len(p))
	defer buffer.Release()
	buffer.Write([]byte{0x17, 0x03, 0x03})
	binary.Write(buffer, binary.BigEndian, uint16(len(p)))
	buffer.Write(p)
	_, err := c.Conn.Write(buffer.Bytes())
	return len(p), err
}

func (c *TLSObfsServer) Upstream() any { return c.Conn }

func NewTLSObfsServer(conn net.Conn) net.Conn {
	return &TLSObfsServer{Conn: conn, firstRequest: true, firstResponse: true}
}

func makeTLSServerHello(payload []byte) []byte {
	var randomBytes [28]byte
	var sessionID [32]byte
	_, _ = rand.Read(randomBytes[:])
	_, _ = rand.Read(sessionID[:])
	var buffer bytes.Buffer
	buffer.WriteByte(0x16)
	binary.Write(&buffer, binary.BigEndian, uint16(0x0301))
	binary.Write(&buffer, binary.BigEndian, uint16(91))
	buffer.Write([]byte{2, 0, 0, 87, 0x03, 0x03})
	binary.Write(&buffer, binary.BigEndian, uint32(time.Now().Unix()))
	buffer.Write(randomBytes[:])
	buffer.WriteByte(32)
	buffer.Write(sessionID[:])
	buffer.Write([]byte{0xcc, 0xa8, 0, 0, 0, 0xff, 1, 0, 1, 0, 0, 0x17, 0, 0, 0, 0x0b, 0, 2, 1, 0})
	buffer.Write([]byte{0x14, 0x03, 0x03, 0, 1, 1})
	buffer.Write([]byte{0x16, 0x03, 0x03})
	binary.Write(&buffer, binary.BigEndian, uint16(len(payload)))
	buffer.Write(payload)
	return buffer.Bytes()
}
