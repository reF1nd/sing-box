package transport

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing/common/x/list"
)

type ConnPoolMode int

const (
	ConnPoolSingle ConnPoolMode = iota
	ConnPoolOrdered
)

type ConnPoolOptions[T comparable] struct {
	Mode    ConnPoolMode
	IsAlive func(T) bool
	Close   func(T, error)
}

type ConnPool[T comparable] struct {
	options ConnPoolOptions[T]

	access sync.Mutex
	closed bool
	state  *connPoolState[T]
}

type connPoolState[T comparable] struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	all map[T]struct{}

	idle         list.List[T]
	idleElements map[T]*list.Element[T]

	shared        T
	hasShared     bool
	sharedClaimed bool
	sharedCtx     context.Context
	sharedCancel  context.CancelCauseFunc

	connecting *connPoolConnect[T]
}

type connPoolConnect[T comparable] struct {
	done chan struct{}
	err  error
}

func NewConnPool[T comparable](options ConnPoolOptions[T]) *ConnPool[T] {
	return &ConnPool[T]{
		options: options,
		state:   newConnPoolState[T](options.Mode),
	}
}

func newConnPoolState[T comparable](mode ConnPoolMode) *connPoolState[T] {
	ctx, cancel := context.WithCancelCause(context.Background())
	state := &connPoolState[T]{
		ctx:    ctx,
		cancel: cancel,
		all:    make(map[T]struct{}),
	}
	if mode == ConnPoolOrdered {
		state.idleElements = make(map[T]*list.Element[T])
	}
	return state
}

func (p *ConnPool[T]) Acquire(ctx context.Context, dial func(context.Context) (T, error)) (T, bool, error) {
	switch p.options.Mode {
	case ConnPoolSingle:
		conn, _, created, err := p.acquireShared(ctx, dial)
		return conn, created, err
	case ConnPoolOrdered:
		return p.acquireOrdered(ctx, dial)
	default:
		var zero T
		return zero, false, net.ErrClosed
	}
}

func (p *ConnPool[T]) AcquireShared(ctx context.Context, dial func(context.Context) (T, error)) (T, context.Context, bool, error) {
	if p.options.Mode != ConnPoolSingle {
		var zero T
		return zero, nil, false, net.ErrClosed
	}
	return p.acquireShared(ctx, dial)
}

func (p *ConnPool[T]) Release(conn T, reuse bool) {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		p.options.Close(conn, net.ErrClosed)
		return
	}
	state := p.state
	if _, tracked := state.all[conn]; !tracked {
		p.access.Unlock()
		p.options.Close(conn, net.ErrClosed)
		return
	}
	if !reuse || !p.options.IsAlive(conn) {
		p.removeConn(state, conn, net.ErrClosed)
		p.access.Unlock()
		p.options.Close(conn, net.ErrClosed)
		return
	}
	if p.options.Mode == ConnPoolOrdered {
		if _, loaded := state.idleElements[conn]; !loaded {
			state.idleElements[conn] = state.idle.PushBack(conn)
		}
	}
	p.access.Unlock()
}

func (p *ConnPool[T]) Invalidate(conn T, cause error) {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		p.options.Close(conn, cause)
		return
	}
	state := p.state
	if _, tracked := state.all[conn]; !tracked {
		p.access.Unlock()
		return
	}
	p.removeConn(state, conn, cause)
	p.access.Unlock()
	p.options.Close(conn, cause)
}

// removeConn must be called with p.access held.
func (p *ConnPool[T]) removeConn(state *connPoolState[T], conn T, cause error) {
	delete(state.all, conn)
	switch p.options.Mode {
	case ConnPoolSingle:
		if state.hasShared && state.shared == conn {
			var zero T
			state.shared = zero
			state.hasShared = false
			state.sharedClaimed = false
			state.sharedCtx = nil
			if state.sharedCancel != nil {
				state.sharedCancel(cause)
				state.sharedCancel = nil
			}
		}
	case ConnPoolOrdered:
		if element, loaded := state.idleElements[conn]; loaded {
			state.idle.Remove(element)
			delete(state.idleElements, conn)
		}
	}
}

func (p *ConnPool[T]) Reset() {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		return
	}
	oldState := p.state
	p.state = newConnPoolState[T](p.options.Mode)
	p.access.Unlock()

	p.closeState(oldState, net.ErrClosed)
}

func (p *ConnPool[T]) Close() error {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		return nil
	}
	p.closed = true
	oldState := p.state
	p.state = nil
	p.access.Unlock()

	p.closeState(oldState, net.ErrClosed)
	return nil
}

func (p *ConnPool[T]) acquireOrdered(ctx context.Context, dial func(context.Context) (T, error)) (T, bool, error) {
	var zero T
	for {
		p.access.Lock()
		if p.closed {
			p.access.Unlock()
			return zero, false, net.ErrClosed
		}
		current := p.state
		if element := current.idle.Front(); element != nil {
			conn := current.idle.Remove(element)
			delete(current.idleElements, conn)
			if p.options.IsAlive(conn) {
				p.access.Unlock()
				return conn, false, nil
			}
			delete(current.all, conn)
			p.access.Unlock()
			p.options.Close(conn, net.ErrClosed)
			continue
		}
		p.access.Unlock()

		dialCtx, dialCancel := context.WithCancelCause(ctx)
		stopStateCancel := context.AfterFunc(current.ctx, func() {
			dialCancel(context.Cause(current.ctx))
		})
		conn, err := dial(dialCtx)
		stateCancelStopped := stopStateCancel()
		dialErr := context.Cause(dialCtx)
		if dialErr == nil && !stateCancelStopped {
			dialErr = context.Cause(current.ctx)
		}
		dialCancel(nil)
		if err != nil {
			if dialErr != nil {
				return zero, false, dialErr
			}
			return zero, false, err
		}
		if dialErr != nil {
			p.options.Close(conn, dialErr)
			return zero, false, dialErr
		}

		p.access.Lock()
		if p.closed {
			p.access.Unlock()
			p.options.Close(conn, net.ErrClosed)
			return zero, false, net.ErrClosed
		}
		if p.state != current {
			p.access.Unlock()
			p.options.Close(conn, net.ErrClosed)
			return zero, false, net.ErrClosed
		}
		current.all[conn] = struct{}{}
		p.access.Unlock()
		return conn, true, nil
	}
}

func (p *ConnPool[T]) acquireShared(ctx context.Context, dial func(context.Context) (T, error)) (T, context.Context, bool, error) {
	var zero T
	for {
		p.access.Lock()
		if p.closed {
			p.access.Unlock()
			return zero, nil, false, net.ErrClosed
		}
		current := p.state
		if current.hasShared {
			conn := current.shared
			if p.options.IsAlive(conn) {
				created := !current.sharedClaimed
				current.sharedClaimed = true
				connCtx := current.sharedCtx
				p.access.Unlock()
				return conn, connCtx, created, nil
			}
			p.removeConn(current, conn, net.ErrClosed)
			p.access.Unlock()
			p.options.Close(conn, net.ErrClosed)
			continue
		}

		startDial := current.connecting == nil
		if startDial {
			current.connecting = &connPoolConnect[T]{done: make(chan struct{})}
		}
		state := current.connecting
		p.access.Unlock()

		if startDial {
			go p.connectSingle(current, state, ctx, dial)
		}

		select {
		case <-state.done:
			conn, connCtx, created, retry, err := p.collectShared(current, state, startDial)
			if retry {
				continue
			}
			return conn, connCtx, created, err
		case <-ctx.Done():
			return zero, nil, false, ctx.Err()
		case <-current.ctx.Done():
			p.access.Lock()
			closed := p.closed
			p.access.Unlock()
			if closed {
				return zero, nil, false, net.ErrClosed
			}
		}
	}
}

func (p *ConnPool[T]) connectSingle(current *connPoolState[T], state *connPoolConnect[T], ctx context.Context, dial func(context.Context) (T, error)) {
	dialCtx, dialCancel := context.WithCancelCause(ctx)
	stopStateCancel := context.AfterFunc(current.ctx, func() {
		dialCancel(context.Cause(current.ctx))
	})
	conn, err := dial(dialCtx)
	stateCancelStopped := stopStateCancel()
	dialErr := context.Cause(dialCtx)
	if dialErr == nil && !stateCancelStopped {
		dialErr = context.Cause(current.ctx)
	}
	dialCancel(nil)
	if dialErr != nil {
		if err == nil {
			p.options.Close(conn, dialErr)
		}
		err = dialErr
	}

	var closeErr error
	p.access.Lock()
	current.connecting = nil
	if err != nil {
		state.err = err
	} else if p.closed {
		closeErr = net.ErrClosed
		state.err = closeErr
	} else if p.state != current {
		closeErr = net.ErrClosed
		state.err = closeErr
	} else {
		sharedCtx, sharedCancel := context.WithCancelCause(current.ctx)
		current.shared = conn
		current.hasShared = true
		current.sharedCtx = sharedCtx
		current.sharedCancel = sharedCancel
		current.all[conn] = struct{}{}
	}
	p.access.Unlock()

	if closeErr != nil {
		p.options.Close(conn, closeErr)
	}
	close(state.done)
}

func (p *ConnPool[T]) collectShared(current *connPoolState[T], state *connPoolConnect[T], startDial bool) (T, context.Context, bool, bool, error) {
	var zero T

	p.access.Lock()
	if state.err != nil {
		err := state.err
		p.access.Unlock()
		if startDial {
			return zero, nil, false, false, err
		}
		return zero, nil, false, true, nil
	}
	if p.closed {
		p.access.Unlock()
		return zero, nil, false, false, net.ErrClosed
	}
	if p.state != current {
		p.access.Unlock()
		return zero, nil, false, false, net.ErrClosed
	}
	if !current.hasShared {
		p.access.Unlock()
		return zero, nil, false, true, nil
	}

	conn := current.shared
	if !p.options.IsAlive(conn) {
		p.removeConn(current, conn, net.ErrClosed)
		p.access.Unlock()
		p.options.Close(conn, net.ErrClosed)
		return zero, nil, false, true, nil
	}

	created := !current.sharedClaimed
	current.sharedClaimed = true
	connCtx := current.sharedCtx
	p.access.Unlock()
	return conn, connCtx, created, false, nil
}

func (p *ConnPool[T]) closeState(state *connPoolState[T], cause error) {
	state.cancel(cause)
	for conn := range state.all {
		p.options.Close(conn, cause)
	}
}
