package local

import (
	"context"
	"errors"

	mDNS "github.com/miekg/dns"
)

var errResolvedUnavailable = errors.New("resolved interface unavailable")

type ResolvedResolver interface {
	Start() error
	Close() error
	Reset()
	Environment() []string
	Fallback() bool
	Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error)
	ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error))
}
