//go:build with_quic

package main

import (
	std_bufio "bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEarlyConnectUDPHTTP1(t *testing.T) {
	startForwardProxy(t)
	echo := startUDPEcho(t)
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(serverPort)))
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := []byte("GET " + connectUDPPath(echo) + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nProxy-Authorization: " + proxyAuthorization + "\r\n\r\n")
	request = append(request, 0, 5, 0, 'p', 'i', 'n', 'g')
	_, err = conn.Write(request)
	require.NoError(t, err)
	reader := std_bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)
	require.Equal(t, "ping", string(readDatagramCapsule(t, reader)))
}

func TestEarlyConnectUDPHTTP2(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, []int{1, 2}, nil)
	echo := startUDPEcho(t)
	clientConn := dialHTTP2Proxy(t, serverPort)
	pipeReader, pipeWriter := io.Pipe()
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: "example.org", Path: connectUDPPath(echo)},
		Host:   "example.org",
		Header: http.Header{
			":protocol":           []string{"connect-udp"},
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{proxyAuthorization},
		},
		Body: pipeReader,
	}
	go pipeWriter.Write([]byte{0, 5, 0, 'p', 'i', 'n', 'g'})
	response, err := clientConn.RoundTrip(request)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	done := make(chan []byte, 1)
	go func() {
		done <- readDatagramCapsule(t, std_bufio.NewReader(response.Body))
	}()
	select {
	case payload := <-done:
		require.Equal(t, "ping", string(payload))
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func testEarlyConnectUDPHTTP3(t *testing.T, datagram bool) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, []int{1, 2, 3}, nil)
	echo := startUDPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn := dialHTTP3Proxy(t, serverPort, datagram)
	stream, err := clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	err = stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		URL:    &url.URL{Scheme: "https", Host: "example.org", Path: connectUDPPath(echo)},
		Host:   "example.org",
		Header: http.Header{
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{proxyAuthorization},
		},
	})
	require.NoError(t, err)
	if datagram {
		err = stream.SendDatagram([]byte{0, 'p', 'i', 'n', 'g'})
		require.NoError(t, err)
	} else {
		writeDatagramCapsule(t, stream, []byte("ping"))
	}
	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	if datagram {
		payload, err := stream.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, "\x00ping", string(payload))
	} else {
		stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		require.Equal(t, "ping", string(readDatagramCapsule(t, std_bufio.NewReader(stream))))
	}
}

func TestEarlyConnectUDPHTTP3Datagram(t *testing.T) { testEarlyConnectUDPHTTP3(t, true) }
func TestEarlyConnectUDPHTTP3Capsule(t *testing.T)  { testEarlyConnectUDPHTTP3(t, false) }
