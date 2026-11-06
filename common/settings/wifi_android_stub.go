//go:build linux && !android

package settings

import (
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

func newAndroidWIFIMonitor(logger logger.ContextLogger, callback func(adapter.WIFIState)) (WIFIMonitor, error) {
	return nil, os.ErrInvalid
}
