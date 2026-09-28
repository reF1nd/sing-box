//go:build !linux && !windows

//nolint:unused
package settings

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

type stubWIFIMonitor struct{}

func NewWIFIMonitor(logger logger.ContextLogger, callback func(adapter.WIFIState)) (WIFIMonitor, error) {
	return nil, os.ErrInvalid
}

func (m *stubWIFIMonitor) ReadWIFIState(ctx context.Context) adapter.WIFIState {
	return adapter.WIFIState{}
}

func (m *stubWIFIMonitor) Start() error {
	return nil
}

func (m *stubWIFIMonitor) Close() error {
	return nil
}
