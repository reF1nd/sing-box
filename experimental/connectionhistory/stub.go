//go:build !with_connection_history

package connectionhistory

import (
	"context"

	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func New(_ context.Context, _ log.ContextLogger, _ *trafficcontrol.Manager, _ option.ConnectionHistoryOptions) (Service, error) {
	return nil, E.New("connection history is not included in this build, rebuild with -tags ", BuildTag)
}
