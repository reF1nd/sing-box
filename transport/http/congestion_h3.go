//go:build with_quic

package http

import (
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
)

type h3CongestionContextKey struct{}

func configureH3Congestion(config *quic.Config, algorithm option.H3CongestionControl) {
	if algorithm == option.H3CongestionCubic {
		config.CongestionControl = quic.CongestionControlCubic
	}
}

func applyH3Congestion(conn *quic.Conn, algorithm option.H3CongestionControl, server bool) {
	if algorithm == option.H3CongestionBBR || server && (algorithm == "" || algorithm == option.H3CongestionNone) {
		conn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard))
	}
}
