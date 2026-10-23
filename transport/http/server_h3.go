//go:build with_quic

package http

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

func init() {
	ConfigureHTTP3ListenerFunc = func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.QUICOptions, congestionControl option.H3CongestionControl) (io.Closer, error) {
		err := qtls.ConfigureHTTP3(tlsConfig)
		if err != nil {
			return nil, err
		}
		udpConn, err := listener.ListenUDP()
		if err != nil {
			return nil, err
		}
		listenerCtx := ctx
		quicConfig := httpclient.NewQUICConfig(options)
		if quicConfig.MaxIncomingStreams == 0 {
			quicConfig.MaxIncomingStreams = 1 << 60
		}
		quicConfig.Allow0RTT = true
		quicConfig.DisablePathManager = true
		quicConfig.EnableDatagrams = true
		quicListener, err := qtls.ListenEarly(udpConn, tlsConfig, quicConfig)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		http3Server := &http3.Server{
			Handler:         handler,
			EnableDatagrams: true,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				applyH3Congestion(listenerCtx, conn, congestionControl, true)
				ctx = context.WithValue(ctx, h3CongestionContextKey{}, congestionControl)
				return log.ContextWithNewID(ctx)
			},
		}
		go func() {
			serveErr := http3Server.ServeListener(quicListener)
			udpConn.Close()
			if serveErr != nil && !E.IsClosedOrCanceled(serveErr) {
				logger.Error("http3 server closed: ", serveErr)
			}
		}()
		return quicListener, nil
	}
	HTTP3StreamFunc = func(ctx context.Context, writer http.ResponseWriter) (DatagramStream, bool) {
		streamer, isStreamer := writer.(http3.HTTPStreamer)
		if !isStreamer {
			return nil, false
		}
		settingser, isSettingser := writer.(http3.Settingser)
		if !isSettingser {
			return nil, false
		}
		select {
		case <-settingser.ReceivedSettings():
		case <-ctx.Done():
			return nil, false
		}
		return &datagramStream{
			Stream:             streamer.HTTPStream(),
			datagramsEnabled:   settingser.Settings().EnableDatagrams,
			bypassIPCongestion: ctx.Value(h3CongestionContextKey{}) == option.H3CongestionNone,
		}, true
	}
}

type datagramStream struct {
	*http3.Stream
	datagramsEnabled   bool
	bypassIPCongestion bool
	writeAccess        sync.Mutex
	closed             atomic.Bool
	closeOnce          sync.Once
	closeErr           error
}

func (s *datagramStream) Write(p []byte) (int, error) {
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	return s.Stream.Write(p)
}

func (s *datagramStream) SendDatagram(payload []byte) error { return s.sendDatagram(payload, false) }

func (s *datagramStream) SendIPDatagram(payload []byte) error {
	return s.sendDatagram(payload, s.bypassIPCongestion)
}

func (s *datagramStream) sendDatagram(payload []byte, bypass bool) error {
	if !s.datagramsEnabled {
		return ErrDatagramUnsupported
	}
	if s.closed.Load() {
		return net.ErrClosed
	}
	var err error
	if bypass {
		err = s.Stream.SendDatagramWithoutCongestionControl(payload)
	} else {
		err = s.Stream.SendDatagram(payload)
	}
	if err == nil {
		return nil
	}
	if tooLarge, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
		return &DatagramTooLargeError{MaxPayloadSize: int(tooLarge.MaxDatagramPayloadSize) - VarintLen(uint64(s.Stream.StreamID()/4))}
	}
	return err
}

func (s *datagramStream) Close() error {
	s.closed.Store(true)
	s.closeOnce.Do(func() {
		s.Stream.SetWriteDeadline(time.Now())
		s.writeAccess.Lock()
		s.Stream.CancelRead(0)
		s.closeErr = s.Stream.Close()
		s.writeAccess.Unlock()
	})
	return s.closeErr
}
