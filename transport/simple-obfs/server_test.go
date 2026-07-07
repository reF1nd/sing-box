package obfs

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func testObfsLoopback(t *testing.T, client net.Conn, server net.Conn) {
	t.Helper()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	request := []byte("client payload")
	response := []byte("server payload")
	writeResult := make(chan error, 1)
	go func() {
		_, err := client.Write(request)
		writeResult <- err
	}()
	receivedRequest := make([]byte, len(request))
	_, err := io.ReadFull(server, receivedRequest)
	require.NoError(t, err)
	require.NoError(t, <-writeResult)
	require.Equal(t, request, receivedRequest)
	go func() {
		_, err := server.Write(response)
		writeResult <- err
	}()
	receivedResponse := make([]byte, len(response))
	_, err = io.ReadFull(client, receivedResponse)
	require.NoError(t, err)
	require.NoError(t, <-writeResult)
	require.Equal(t, response, receivedResponse)
}

func TestHTTPObfsServerLoopback(t *testing.T) {
	clientConn, serverConn := tcpPair(t)
	testObfsLoopback(t, NewHTTPObfs(clientConn, "example.com", "80"), NewHTTPObfsServer(serverConn))
}

func TestTLSObfsServerLoopback(t *testing.T) {
	clientConn, serverConn := tcpPair(t)
	testObfsLoopback(t, NewTLSObfs(clientConn, "example.com"), NewTLSObfsServer(serverConn))
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	return client, <-accepted
}
