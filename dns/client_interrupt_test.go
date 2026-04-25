package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type interruptMarkTransport struct {
	adapter.DNSTransport
	external         bool
	resourceDownload bool
}

func (t *interruptMarkTransport) Tag() string { return "interrupt" }

func (t *interruptMarkTransport) Environment() []string { return nil }

func (t *interruptMarkTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.external = interrupt.IsExternalConnectionFromContext(ctx)
	t.resourceDownload = interrupt.IsResourceDownloadFromContext(ctx)
	return FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 60), nil
}

func TestExchangeClearsInterruptMarks(t *testing.T) {
	client := NewClient(ClientOptions{Context: t.Context(), DisableCache: true})
	transport := &interruptMarkTransport{}
	ctx := interrupt.ContextWithIsExternalConnection(t.Context(), true)
	ctx = interrupt.ContextWithIsResourceDownload(ctx, true)
	_, err := client.Exchange(ctx, transport, dedupQuestion(1), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.False(t, transport.external)
	require.False(t, transport.resourceDownload)
}
