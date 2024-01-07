package inbound

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/redir"
	"github.com/sagernet/sing-box/common/script"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Redirect struct {
	myInboundAdapter
	scripts []*script.Script
}

func NewRedirect(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.RedirectInboundOptions) (*Redirect, error) {
	redirect := &Redirect{
		myInboundAdapter: myInboundAdapter{
			protocol:      C.TypeRedirect,
			network:       []string{N.NetworkTCP},
			ctx:           ctx,
			router:        router,
			logger:        logger,
			tag:           tag,
			listenOptions: options.ListenOptions,
		},
	}
	redirect.connHandler = redirect
	if len(options.Scripts) > 0 {
		redirect.scripts = make([]*script.Script, len(options.Scripts))
		for i, scriptOptions := range options.Scripts {
			s, err := script.New(ctx, logger, scriptOptions)
			if err != nil {
				return nil, E.Cause(err, "create script[", i, "] failed")
			}
			redirect.scripts[i] = s
		}
	}
	return redirect, nil
}

func (r *Redirect) Start() error {
	err := r.myInboundAdapter.Start()
	if err != nil {
		return err
	}
	for i, s := range r.scripts {
		r.logger.Debug("start: run script[", i, "]")
		err := s.Start()
		if err != nil {
			return E.Cause(err, "start: run script[", i, "] failed")
		}
	}
	return nil
}

func (r *Redirect) Close() error {
	for i, s := range r.scripts {
		r.logger.Debug("close: run script[", i, "]")
		err := s.Close()
		if err != nil {
			return E.Cause(err, "close: run script[", i, "] failed")
		}
	}
	return r.myInboundAdapter.Close()
}

func (r *Redirect) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	destination, err := redir.GetOriginalDestination(conn)
	if err != nil {
		return E.Cause(err, "get redirect destination")
	}
	metadata.Destination = M.SocksaddrFromNetIP(destination)
	return r.newConnection(ctx, conn, metadata)
}
