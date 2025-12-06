//go:build go1.23

package dialer

import (
	"net"
	"time"
)

func setKeepAliveConfig(dialer *net.Dialer, idle time.Duration, interval time.Duration, count int) {
	dialer.KeepAliveConfig = net.KeepAliveConfig{
		Enable:   true,
		Idle:     idle,
		Interval: interval,
		Count:    count,
	}
}
