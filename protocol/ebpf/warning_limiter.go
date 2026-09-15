//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const warningInterval = 10 * time.Second

type warningLimiter struct {
	access      sync.Mutex
	next        time.Time
	suppressed  uint64
	lastMessage string
	lastAt      time.Time
}

func (l *warningLimiter) allow(now time.Time) (bool, uint64) {
	l.access.Lock()
	defer l.access.Unlock()
	if now.Before(l.next) {
		l.suppressed++
		return false, 0
	}
	suppressed := l.suppressed
	l.suppressed = 0
	l.next = now.Add(warningInterval)
	return true, suppressed
}

type warningLogger interface {
	Warn(args ...any)
}

type contextErrorLogger interface {
	ErrorContext(ctx context.Context, args ...any)
}

// record keeps the most recent occurrence for diagnostics regardless of
// whether the rate limiter goes on to actually log this one: an operator
// asking "what's the last error on this path" wants to know it happened
// seconds ago even if the log line itself was suppressed as a repeat.
func (l *warningLimiter) record(now time.Time, message ...any) {
	l.access.Lock()
	l.lastMessage = fmt.Sprint(message...)
	l.lastAt = now
	l.access.Unlock()
}

// last reports the most recently recorded message and when, for diagnostics.
// The zero time means nothing has ever been recorded.
func (l *warningLimiter) last() (string, time.Time) {
	l.access.Lock()
	defer l.access.Unlock()
	return l.lastMessage, l.lastAt
}

func (l *warningLimiter) warn(logger warningLogger, message ...any) {
	now := time.Now()
	l.record(now, message...)
	allowed, suppressed := l.allow(now)
	if !allowed {
		return
	}
	if suppressed > 0 {
		message = append(message, " (", suppressed, " similar warnings suppressed)")
	}
	logger.Warn(message...)
}

func (l *warningLimiter) errorContext(logger contextErrorLogger, ctx context.Context, message ...any) {
	now := time.Now()
	l.record(now, message...)
	allowed, suppressed := l.allow(now)
	if !allowed {
		return
	}
	if suppressed > 0 {
		message = append(message, " (", suppressed, " similar errors suppressed)")
	}
	logger.ErrorContext(ctx, message...)
}

type udpWarningLimiters struct {
	packetInfo          warningLimiter
	originalDestination warningLimiter
	cleanup             warningLimiter
	replySocketCapacity warningLimiter
}

type interfaceWarningLimiters struct {
	inventory        warningLimiter
	defaultInterface warningLimiter
	topology         warningLimiter
	infrastructure   warningLimiter
	hostPolicy       warningLimiter
	reconcile        warningLimiter
	fakeIPICMPRoute  warningLimiter
}
