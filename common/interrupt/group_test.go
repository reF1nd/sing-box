package interrupt

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type callbackCloser func() error

func (c callbackCloser) Close() error { return c() }

func TestInterruptKeepsProviderAndClosesOutsideLock(t *testing.T) {
	group := NewGroup()
	var detach func()
	closed := make(chan struct{})
	element := group.connections.PushBack(&groupConnItem{conn: callbackCloser(func() error { detach(); close(closed); return nil }), isExternal: true})
	detach = func() {
		group.access.Lock()
		defer group.access.Unlock()
		group.connections.Remove(element)
	}
	left, right := net.Pipe()
	defer right.Close()
	provider := group.NewConn(left, true, true)
	defer provider.Close()
	done := make(chan struct{})
	go func() { group.Interrupt(true); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close callback deadlocked with interrupt group")
	}
	<-closed
	require.Equal(t, 1, group.connections.Len())
}
