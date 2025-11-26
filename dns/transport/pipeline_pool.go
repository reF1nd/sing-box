package transport

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
)

type pipelinePool struct {
	logger                logger.ContextLogger
	enablePipeline        bool
	idleTimeout           time.Duration
	disableKeepAlive      bool
	maxQueries            int
	connections           *ConnPool[*reuseableDNSConn]
	activeConns           []*reuseableDNSConn
	activeAccess          sync.Mutex
	pipelineDetected      atomic.Int32
	consecutiveOutOfOrder int32
	outOfOrderCount       int32
	totalResponses        int32
}

func newReuseableDNSConnPool(maxInflight int) *ConnPool[*reuseableDNSConn] {
	return NewConnPool(ConnPoolOptions[*reuseableDNSConn]{
		Mode:        ConnPoolOrdered,
		MaxInflight: maxInflight,
		IsAlive: func(conn *reuseableDNSConn) bool {
			select {
			case <-conn.done:
				return false
			default:
				return true
			}
		},
		Close: func(conn *reuseableDNSConn, _ error) {
			conn.Close()
		},
	})
}

func (p *pipelinePool) exchange(ctx context.Context, message *mDNS.Msg, createNewConn func(context.Context, *mDNS.Msg) (*mDNS.Msg, error)) (*mDNS.Msg, error) {
	if p.enablePipeline {
		if p.maxQueries == 0 {
			conn := p.getValidConnFromPool()
			if conn != nil {
				response, err := conn.Exchange(ctx, message)
				if err == nil {
					return response, nil
				}
				if ctx.Err() != nil {
					return nil, err
				}
				p.logger.DebugContext(ctx, "retrying query on new connection after reused conn failure: ", err)
			}
			return createNewConn(ctx, message)
		} else {
			conn := p.findAndReserveActiveConn()
			if conn != nil {
				response, err := conn.exchangeWithoutIncrement(ctx, message)
				if err == nil {
					return response, nil
				}
				if ctx.Err() != nil {
					return nil, err
				}
				p.logger.DebugContext(ctx, "retrying query after active conn failure: ", err)
			}

			conn = p.getValidConnFromPool()
			if conn != nil {
				p.addActiveConn(conn)
				response, err := conn.Exchange(ctx, message)
				if err == nil {
					return response, nil
				}
				if ctx.Err() != nil {
					return nil, err
				}
				p.logger.DebugContext(ctx, "retrying query on new connection after pooled conn failure: ", err)
			}

			return createNewConn(ctx, message)
		}
	} else {
		conn := p.getValidConnFromPool()
		if conn != nil {
			response, err := conn.Exchange(ctx, message)
			if err == nil {
				return response, nil
			}
			if ctx.Err() != nil {
				return nil, err
			}
			p.logger.DebugContext(ctx, "retrying query on new connection after reused conn failure: ", err)
		}
		return createNewConn(ctx, message)
	}
}

func (p *pipelinePool) closePool() error {
	if p.connections != nil {
		return p.connections.Close()
	}
	return nil
}

func (p *pipelinePool) resetPool() {
	if p.connections != nil {
		p.connections.Reset()
	}
	p.activeAccess.Lock()
	activeConns := p.activeConns
	p.activeConns = nil
	p.activeAccess.Unlock()
	for _, conn := range activeConns {
		conn.Close()
	}
	p.pipelineDetected.Store(0)
	atomic.StoreInt32(&p.consecutiveOutOfOrder, 0)
	atomic.StoreInt32(&p.outOfOrderCount, 0)
	atomic.StoreInt32(&p.totalResponses, 0)
}

func (p *pipelinePool) getValidConnFromPool() *reuseableDNSConn {
	conn, _, err := p.connections.Acquire(context.Background(), func(_ context.Context) (*reuseableDNSConn, error) {
		return nil, E.New("no pooled connection available")
	})
	if err != nil {
		return nil
	}
	return conn
}

func (p *pipelinePool) findAndReserveActiveConn() *reuseableDNSConn {
	p.activeAccess.Lock()
	defer p.activeAccess.Unlock()

	var bestConn *reuseableDNSConn
	var minQueries int32 = -1
	var closedCount int

	for _, conn := range p.activeConns {
		select {
		case <-conn.done:
			closedCount++
		default:
			if conn.maxQueries <= 0 || conn.activeQueries.Load() < int32(conn.maxQueries) {
				current := conn.activeQueries.Load()
				if minQueries == -1 || current < minQueries {
					minQueries = current
					bestConn = conn
				}
			}
		}
	}

	if bestConn != nil && minQueries == 0 && closedCount == 0 {
		bestConn.activeQueries.Add(1)
		return bestConn
	}

	if closedCount > 0 {
		validConns := make([]*reuseableDNSConn, 0, len(p.activeConns)-closedCount)
		for _, conn := range p.activeConns {
			select {
			case <-conn.done:
			default:
				validConns = append(validConns, conn)
			}
		}
		p.activeConns = validConns
	}

	if bestConn != nil {
		bestConn.activeQueries.Add(1)
	}

	return bestConn
}

func (p *pipelinePool) addActiveConn(conn *reuseableDNSConn) {
	p.activeAccess.Lock()
	defer p.activeAccess.Unlock()

	if slices.Contains(p.activeConns, conn) {
		return
	}

	p.activeConns = append(p.activeConns, conn)
}

func (p *pipelinePool) removeActiveConn(conn *reuseableDNSConn) {
	p.activeAccess.Lock()
	defer p.activeAccess.Unlock()

	for i, c := range p.activeConns {
		if c == conn {
			last := len(p.activeConns) - 1
			p.activeConns[i] = p.activeConns[last]
			p.activeConns = p.activeConns[:last]
			return
		}
	}
}

func (p *pipelinePool) markPipelineDetected() bool {
	return p.pipelineDetected.CompareAndSwap(0, 1)
}

func (p *pipelinePool) isPipelineDetected() bool {
	return p.pipelineDetected.Load() != 0
}

func (p *pipelinePool) getDetectionCounters() (*int32, *int32, *int32) {
	return &p.consecutiveOutOfOrder, &p.outOfOrderCount, &p.totalResponses
}
