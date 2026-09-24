package local

import (
	"context"
	"errors"
	"net/netip"

	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
)

var errResolvedUnavailable = errors.New("resolved interface unavailable")

func NewResolvedResolver(ctx context.Context, logger logger.ContextLogger) (ResolvedResolver, error) {
	return newResolvedResolver(ctx, logger, false)
}

type ResolvedResolver interface {
	Start() error
	Close() error
	Reset()
	Environment() []string
	ServerAddresses() []netip.Addr
	SearchDomains() []string
	Fallback() bool
	ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error))
}
