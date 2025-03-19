package proxyproto

import (
	std_bufio "bufio"
	"errors"
	"net"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/pires/go-proxyproto"
)

const defaultMaxInFlight = 256

type acceptResult struct {
	conn net.Conn
	err  error
}

type Listener struct {
	net.Listener
	AcceptNoHeader bool
	ReadTimeout    time.Duration
	MaxInFlight    int
	Logger         logger.Logger

	initOnce   sync.Once
	sem        chan struct{}
	ready      chan acceptResult
	done       chan struct{}
	acceptDone chan struct{}

	mu        sync.Mutex
	closed    bool
	acceptErr error
	pending   map[net.Conn]struct{}
	wg        sync.WaitGroup
}

func (l *Listener) init() {
	l.initOnce.Do(func() {
		maxInFlight := l.MaxInFlight
		if maxInFlight <= 0 {
			maxInFlight = defaultMaxInFlight
		}
		l.sem = make(chan struct{}, maxInFlight)
		l.ready = make(chan acceptResult)
		l.acceptDone = make(chan struct{})
		l.mu.Lock()
		l.done = make(chan struct{})
		if l.closed {
			close(l.done)
			close(l.acceptDone)
			l.mu.Unlock()
			return
		}
		l.pending = make(map[net.Conn]struct{})
		l.mu.Unlock()
		go l.acceptLoop()
	})
}

func (l *Listener) acceptLoop() {
	defer func() {
		l.wg.Wait()
		close(l.acceptDone)
	}()
	for {
		select {
		case l.sem <- struct{}{}:
		case <-l.done:
			return
		}
		rawConn, err := l.Listener.Accept()
		if err != nil {
			<-l.sem
			//nolint:staticcheck
			if netErr, isNetErr := err.(net.Error); isNetErr && netErr.Temporary() {
				select {
				case l.ready <- acceptResult{err: err}:
					continue
				case <-l.done:
					return
				}
			}
			l.mu.Lock()
			l.acceptErr = err
			l.mu.Unlock()
			return
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			<-l.sem
			_ = rawConn.Close()
			return
		}
		l.pending[rawConn] = struct{}{}
		l.wg.Add(1)
		l.mu.Unlock()
		go l.handleConn(rawConn)
	}
}

func (l *Listener) handleConn(rawConn net.Conn) {
	defer func() {
		<-l.sem
		l.wg.Done()
	}()
	conn, err := l.readHeaderConn(rawConn)
	l.mu.Lock()
	_, stillPending := l.pending[rawConn]
	delete(l.pending, rawConn)
	closed := l.closed
	l.mu.Unlock()
	if err != nil {
		if stillPending {
			_ = rawConn.Close()
		}
		if !closed && l.Logger != nil {
			l.Logger.Error(E.Cause(err, "read proxy protocol header"))
		}
		return
	}
	if closed {
		if stillPending {
			_ = conn.Close()
		} else if cachedConn, ok := common.Cast[*bufio.CachedConn](conn); ok {
			cachedConn.ReadCached().Release()
		}
		return
	}
	select {
	case l.ready <- acceptResult{conn: conn}:
	case <-l.done:
		_ = conn.Close()
	}
}

func (l *Listener) readHeaderConn(rawConn net.Conn) (net.Conn, error) {
	readTimeout := l.ReadTimeout
	if readTimeout == 0 {
		readTimeout = C.TCPConnectTimeout
	}
	if readTimeout > 0 {
		if err := rawConn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return nil, &Error{err}
		}
	}
	bufReader := std_bufio.NewReader(rawConn)
	header, err := proxyproto.Read(bufReader)
	if err != nil && !(l.AcceptNoHeader && errors.Is(err, proxyproto.ErrNoProxyProtocol)) {
		return nil, &Error{err}
	}
	if readTimeout > 0 {
		if err = rawConn.SetReadDeadline(time.Time{}); err != nil {
			return nil, &Error{err}
		}
	}
	conn := rawConn
	if bufReader.Buffered() > 0 {
		cache := buf.NewSize(bufReader.Buffered())
		_, err = cache.ReadFullFrom(bufReader, cache.FreeLen())
		if err != nil {
			cache.Release()
			return nil, &Error{err}
		}
		conn = bufio.NewCachedConn(conn, cache)
	}
	if header != nil && (header.SourceAddr != nil || header.DestinationAddr != nil) {
		var source, destination M.Socksaddr
		if header.SourceAddr != nil {
			source = M.SocksaddrFromNet(header.SourceAddr).Unwrap()
		} else {
			source = M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
		}
		if header.DestinationAddr != nil {
			destination = M.SocksaddrFromNet(header.DestinationAddr).Unwrap()
		} else {
			destination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
		}
		return &bufio.AddrConn{
			Conn:        conn,
			Source:      source,
			Destination: destination,
		}, nil
	}
	return conn, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	l.init()
	select {
	case <-l.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case res := <-l.ready:
		return res.conn, res.err
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.acceptDone:
		select {
		case res := <-l.ready:
			return res.conn, res.err
		default:
			l.mu.Lock()
			err := l.acceptErr
			l.mu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return nil, err
		}
	}
}

func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return l.Listener.Close()
	}
	l.closed = true
	done := l.done
	pending := make([]net.Conn, 0, len(l.pending))
	for conn := range l.pending {
		pending = append(pending, conn)
	}
	l.pending = nil
	l.mu.Unlock()

	if done != nil {
		close(done)
	}
	err := l.Listener.Close()
	for _, conn := range pending {
		_ = conn.Close()
	}
	return err
}

var _ net.Error = (*Error)(nil)

type Error struct {
	error
}

func (e *Error) Unwrap() error {
	return e.error
}

func (e *Error) Timeout() bool {
	var netErr net.Error
	return errors.As(e.error, &netErr) && netErr.Timeout()
}

func (e *Error) Temporary() bool {
	return true
}
