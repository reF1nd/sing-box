//go:build with_quic

package http

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestBuildH3CongestionControlSelection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const initialPacketSize congestion.ByteCount = 1200

	// Client omitted, new_reno, and none rely on native quic-go NewReno (nil override).
	for _, alg := range []option.H3CongestionControl{"", option.H3CongestionNewReno, option.H3CongestionNone} {
		require.Nil(t, buildH3CongestionControl(ctx, initialPacketSize, alg, false), "client %q", alg)
	}

	// Server new_reno relies on native quic-go NewReno (nil override).
	require.Nil(t, buildH3CongestionControl(ctx, initialPacketSize, option.H3CongestionNewReno, true))

	// Server omitted, none, bbr and client bbr install sing-quic BBR sender.
	for _, tc := range []struct {
		alg    option.H3CongestionControl
		server bool
	}{
		{"", true},
		{option.H3CongestionNone, true},
		{option.H3CongestionBBR, true},
		{option.H3CongestionBBR, false},
	} {
		sender := buildH3CongestionControl(ctx, initialPacketSize, tc.alg, tc.server)
		require.NotNil(t, sender, "alg=%q server=%v", tc.alg, tc.server)
		rt := reflect.TypeOf(sender).Elem()
		require.Contains(t, rt.PkgPath(), "sing-quic/congestion_meta2")
		require.Equal(t, "bbrSender", rt.Name())
	}

	// Both client and server cubic install sing-quic/congestion_meta1 cubicSender.
	for _, server := range []bool{false, true} {
		sender := buildH3CongestionControl(ctx, initialPacketSize, option.H3CongestionCubic, server)
		require.NotNil(t, sender, "cubic server=%v", server)
		rt := reflect.TypeOf(sender).Elem()
		require.Contains(t, rt.PkgPath(), "sing-quic/congestion_meta1")
		require.Equal(t, "cubicSender", rt.Name())

		// Simulate quic-go's installation step (SetMaxDatagramSize(initialPacketSize))
		// before PMTU growth 1200 -> 1452 so an accidental 1280 default would panic.
		sender.SetMaxDatagramSize(initialPacketSize)
		now := monotime.Now()
		sender.OnPacketSent(now, 0, 1, 1200, true)
		sender.SetMaxDatagramSize(1452)
		sender.OnPacketSent(now.Add(10*time.Millisecond), 1200, 2, 1452, true)
	}
}
