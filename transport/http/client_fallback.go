package http

import (
	"context"
	"errors"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const http3FallbackTimeout = 5 * time.Second

func (c *Client) http3AttemptContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.disableVersionFallback {
		return context.WithCancel(ctx)
	}
	// Leave time for TCP when UDP is blackholed. The caller's deadline still
	// bounds the whole operation, including the lower-version attempts.
	timeout := http3FallbackTimeout
	if deadline, loaded := ctx.Deadline(); loaded {
		timeout = min(timeout, time.Until(deadline)/2)
	}
	return context.WithTimeout(ctx, timeout)
}

func http3AttemptError(ctx context.Context, attemptCtx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.DeadlineExceeded) && errors.Is(attemptCtx.Err(), context.DeadlineExceeded) {
		return E.Cause1(ErrHTTP3Unavailable, err)
	}
	return err
}

// ReportTunnelError makes a failed HTTP/3 tunnel eligible for version fallback
// on the next connection attempt. Callers must exclude intentional shutdowns
// and network changes before reporting a session error.
func (c *Client) ReportTunnelError(err error) {
	if !c.disableVersionFallback && errors.Is(err, ErrHTTP3Unavailable) {
		c.markHTTP3Broken()
	}
}
