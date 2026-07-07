package obfs

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type HTTPObfsServer struct {
	net.Conn
	buffer        []byte
	reader        *bufio.Reader
	firstRequest  bool
	firstResponse bool
}

func (c *HTTPObfsServer) Read(p []byte) (int, error) {
	if len(c.buffer) > 0 {
		n := copy(p, c.buffer)
		c.buffer = c.buffer[n:]
		return n, nil
	}
	if c.firstRequest {
		reader := bufio.NewReader(c.Conn)
		request, err := http.ReadRequest(reader)
		if err != nil {
			return 0, err
		}
		if request.Method != http.MethodGet || request.Header.Get("Connection") != "Upgrade" {
			request.Body.Close()
			return 0, io.EOF
		}
		body, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return 0, err
		}
		c.reader = reader
		c.firstRequest = false
		n := copy(p, body)
		c.buffer = body[n:]
		return n, nil
	}
	return c.reader.Read(p)
}

func (c *HTTPObfsServer) Write(p []byte) (int, error) {
	if c.firstResponse {
		var random [16]byte
		_, _ = rand.Read(random[:])
		response := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\nDate: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", time.Now().Format(time.RFC1123), base64.URLEncoding.EncodeToString(random[:]))
		if _, err := c.Conn.Write([]byte(response)); err != nil {
			return 0, err
		}
		c.firstResponse = false
	}
	return c.Conn.Write(p)
}

func (c *HTTPObfsServer) Upstream() any { return c.Conn }

func NewHTTPObfsServer(conn net.Conn) net.Conn {
	return &HTTPObfsServer{Conn: conn, firstRequest: true, firstResponse: true}
}
