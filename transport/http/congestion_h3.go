//go:build with_quic

package http

import (
	"context"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/sing-box/option"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common/ntp"
)

type h3CongestionContextKey struct{}

func buildH3CongestionControl(ctx context.Context, initialPacketSize congestion.ByteCount, algorithm option.H3CongestionControl, server bool) congestion.CongestionControl {
	switch algorithm {
	case option.H3CongestionCubic:
		timeFunc := ntp.TimeFuncFromContext(ctx)
		if timeFunc == nil {
			timeFunc = time.Now
		}
		return congestion_meta1.NewCubicSender(
			congestion_meta1.DefaultClock{TimeFunc: timeFunc},
			initialPacketSize,
			false,
		)
	case option.H3CongestionBBR:
		return congestion_meta2.NewBbrSenderWithProfile(initialPacketSize, congestion_meta2.ProfileStandard)
	case "", option.H3CongestionNone:
		if server {
			return congestion_meta2.NewBbrSenderWithProfile(initialPacketSize, congestion_meta2.ProfileStandard)
		}
		return nil
	default:
		return nil
	}
}

func applyH3Congestion(ctx context.Context, conn *quic.Conn, algorithm option.H3CongestionControl, server bool) {
	if sender := buildH3CongestionControl(ctx, conn.InitialPacketSize(), algorithm, server); sender != nil {
		conn.SetCongestionControl(sender)
	}
}
