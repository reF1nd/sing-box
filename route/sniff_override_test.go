package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestSniffOverrideDestinationKeepsQUICCacheKey(t *testing.T) {
	router, metadata := newPreMatchQUICRouter(t, quicSniffCacheTTL)
	router.logger = logger.NOP()
	metadata.Protocol = "quic"
	metadata.SniffHost = "example.com"
	original := metadata.Destination
	router.processQUICSniff(context.Background(), &metadata)
	router.actionSniffOverrideDestination(context.Background(), &metadata, nil, &quicClosePacketConn{}, false)
	require.Equal(t, original, metadata.OriginDestination)
	require.Equal(t, original, metadata.SniffDestination)
	require.Equal(t, M.ParseSocksaddr("example.com:443"), metadata.Destination)
	require.True(t, metadata.DestOverride)
	router.actionSniffOverrideDestination(context.Background(), &metadata, nil, nil, true)
	require.Equal(t, original, metadata.OriginDestination)
	router.wrapQUICSniffIdleCache(metadata, nil)(nil)
	_, loaded := router.lookupQUICSniff(metadata.Source, metadata.Destination)
	require.False(t, loaded)
	require.False(t, adapter.IsFinalAction(&R.RuleActionSniffOverrideDestination{}))
}
