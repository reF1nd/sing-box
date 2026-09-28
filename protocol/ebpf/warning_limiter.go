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
	lastMessage []any
	lastAt      time.Time
}

func (l *warningLimiter) allow(now time.Time) (bool, uint64) {
	l.access.Lock()
	defer l.access.Unlock()
	return l.allowLocked(now)
}

func (l *warningLimiter) observe(now time.Time, message []any) (bool, uint64) {
	l.access.Lock()
	defer l.access.Unlock()
	l.lastMessage = message
	l.lastAt = now
	return l.allowLocked(now)
}

func (l *warningLimiter) allowLocked(now time.Time) (bool, uint64) {
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
	l.lastMessage = message
	l.lastAt = now
	l.access.Unlock()
}

// last reports the most recently recorded message and when, for diagnostics.
// The zero time means nothing has ever been recorded.
func (l *warningLimiter) last() (string, time.Time) {
	l.access.Lock()
	message, at := l.lastMessage, l.lastAt
	l.access.Unlock()
	if at.IsZero() {
		return "", at
	}
	return fmt.Sprint(message...), at
}

func (l *warningLimiter) warn(logger warningLogger, message ...any) {
	allowed, suppressed := l.observe(time.Now(), message)
	if !allowed {
		return
	}
	if suppressed > 0 {
		message = append(message, " (", suppressed, " similar warnings suppressed)")
	}
	logger.Warn(message...)
}

func (l *warningLimiter) errorContext(logger contextErrorLogger, ctx context.Context, message ...any) {
	allowed, suppressed := l.observe(time.Now(), message)
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
