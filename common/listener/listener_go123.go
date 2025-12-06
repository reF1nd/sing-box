//go:build go1.23

package listener

import (
	"net"
	"time"
)

func setKeepAliveConfig(listener *net.ListenConfig, idle time.Duration, interval time.Duration, count int) {
	listener.KeepAliveConfig = net.KeepAliveConfig{
		Enable:   true,
		Idle:     idle,
		Interval: interval,
		Count:    count,
	}
}
