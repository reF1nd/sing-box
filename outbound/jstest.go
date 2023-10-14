//go:build with_jstest

package outbound

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	jg "github.com/sagernet/sing-box/jstest/golang"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/robertkrimen/otto"
)

const DefaultJSTestInterval = 1 * time.Minute

var _ adapter.Outbound = (*JSTest)(nil)

type JSTest struct {
	myOutboundAdapter
	ctx                          context.Context
	tags                         []string
	outbounds                    map[string]adapter.Outbound
	selected                     adapter.Outbound
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	interval                     time.Duration
	jsPath                       string
	jsBase64                     string
	jsGlobalVar                  map[string]any
	jsVM                         *otto.Otto
	jsCtx                        context.Context
	jsCancel                     context.CancelFunc
	jsCloseDone                  chan struct{}
}

func NewJSTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.JSTestOutboundOptions) (adapter.Outbound, error) {
	outbound := &JSTest{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeJSTest,
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: options.Outbounds,
		},
		ctx:                          ctx,
		tags:                         options.Outbounds,
		outbounds:                    make(map[string]adapter.Outbound),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,
		jsPath:                       options.JSPath,
		jsBase64:                     options.JSBase64,
		jsGlobalVar:                  options.JSGlobalVar,
		interval:                     time.Duration(options.Interval),
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	if outbound.jsPath == "" && outbound.jsBase64 == "" {
		return nil, E.New("missing js path or base64")
	}
	if outbound.interval <= 0 {
		outbound.interval = DefaultJSTestInterval
	}
	return outbound, nil
}

func (j *JSTest) Network() []string {
	if j.selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return j.selected.Network()
}

func (j *JSTest) Start() error {
	for i, tag := range j.tags {
		detour, loaded := j.router.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		j.outbounds[tag] = detour
	}

	if j.tag != "" {
		cacheFile := service.FromContext[adapter.CacheFile](j.ctx)
		if cacheFile != nil {
			selected := cacheFile.LoadSelected(j.tag)
			if selected != "" {
				detour, loaded := j.outbounds[selected]
				if loaded {
					j.selected = detour
				}
			}
		}
	}

	if j.selected == nil {
		j.selected = j.outbounds[j.tags[0]]
	}

	// JS
	j.jsVM = otto.New()
	j.jsVM.Interrupt = make(chan func(), 1)
	{
		j.jsVM.Set("log_trace", jg.JSGoLog(j.jsVM, j.logger.Trace))
		j.jsVM.Set("log_debug", jg.JSGoLog(j.jsVM, j.logger.Debug))
		j.jsVM.Set("log_info", jg.JSGoLog(j.jsVM, j.logger.Info))
		j.jsVM.Set("log_warn", jg.JSGoLog(j.jsVM, j.logger.Warn))
		j.jsVM.Set("log_error", jg.JSGoLog(j.jsVM, j.logger.Error))
		j.jsVM.Set("log_fatal", jg.JSGoLog(j.jsVM, j.logger.Fatal))
	}
	var err error
	if j.jsGlobalVar != nil {
		var vv otto.Value
		for k, v := range j.jsGlobalVar {
			if k == "" {
				continue
			}
			vv, err = j.jsVM.ToValue(v)
			if err != nil {
				return E.New("convert js global var: ", err)
			}
			j.jsVM.Set(k, vv)
		}
	}
	var raw []byte
	if j.jsPath != "" {
		raw, err = os.ReadFile(j.jsPath)
		if err != nil {
			return E.New("read js file: ", err)
		}
	} else {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(j.jsBase64))
		if err != nil {
			return E.New("decode js base64: ", err)
		}
		j.jsBase64 = ""
	}
	if len(raw) == 0 {
		return E.New("empty js code")
	}
	_, err = j.jsVM.Run(raw)
	if err != nil {
		return E.New("load js file: ", err)
	}
	j.jsCtx, j.jsCancel = context.WithCancel(j.ctx)
	j.jsCloseDone = make(chan struct{}, 1)
	go func() {
		<-j.jsCtx.Done()
		j.jsVM.Interrupt <- func() {}
		close(j.jsVM.Interrupt)
	}()
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				httpRequest := ctx.Value(jg.HTTPRequestKey).(*jg.HTTPRequest)
				detour, loaded := j.outbounds[httpRequest.Detour]
				if !loaded {
					return nil, E.New("outbound not found: ", httpRequest.Detour)
				}
				return detour.DialContext(ctx, network, M.ParseSocksaddr(address))
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			httpRequest := req.Context().Value(jg.HTTPRequestKey).(*jg.HTTPRequest)
			if httpRequest.DisableRedirect {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	j.jsVM.Set("http_requests", jg.JSGoHTTPRequests(j.jsCtx, j.jsVM, httpClient))
	j.jsVM.Set("urltests", jg.JSGoURLTest(j.jsCtx, j.router, j.jsVM))
	go j.loopTest()

	return nil
}

func (j *JSTest) Close() error {
	if j.jsCtx != nil {
		j.jsCancel()
		<-j.jsCloseDone
		close(j.jsCloseDone)
	}
	return nil
}

func (j *JSTest) loopTest() {
	defer func() {
		j.jsCloseDone <- struct{}{}
	}()
	j.test()
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()
	for {
		select {
		case <-j.jsCtx.Done():
			return
		case <-ticker.C:
			j.test()
		}
	}
}

// function Test(outbounds, now_selected)
//
// Params:
// * outbounds: []string
// * now_selected: string
//
// Returns:
// * result => {value: selected(string), error: string}

type jsResponse struct {
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

func (j *JSTest) test() {
	defer func() {
		err := recover()
		if err != nil {
			j.logger.Error("js test painc: ", err)
		}
	}()
	j.logger.Info("run js test")
	defer j.logger.Info("js test run done")
	value, err := j.jsVM.Call("Test", nil, j.tags, j.selected.Tag())
	if err != nil {
		select {
		case <-j.jsCtx.Done():
			return
		default:
		}
		j.logger.Error("js test run failed: ", err)
		return
	}
	select {
	case <-j.jsCtx.Done():
		return
	default:
	}
	j.logger.Info("js test run success")
	if !value.IsObject() {
		j.logger.Error("js test run: invalid return value: ", fmt.Sprintf("%v", value))
		return
	}
	raw, err := value.Object().MarshalJSON()
	if err != nil {
		j.logger.Error("js test run: invalid return value: ", err)
		return
	}
	var response jsResponse
	err = json.Unmarshal(raw, &response)
	if err != nil {
		j.logger.Error("js test run: invalid return value: ", err)
		return
	}
	if response.Error != "" {
		j.logger.Error("js test run: ", response.Error)
		return
	}
	if response.Value == "" {
		j.logger.Error("js test run: invalid return value: ", response.Value)
		return
	}
	j.SelectOutbound(response.Value)
	j.logger.Info("js test run: select [", response.Value, "]")
}

func (j *JSTest) SelectOutbound(tag string) bool {
	detour, loaded := j.outbounds[tag]
	if !loaded {
		return false
	}
	if j.selected == detour {
		return true
	}
	j.selected = detour
	if j.tag != "" {
		cacheFile := service.FromContext[adapter.CacheFile](j.ctx)
		if cacheFile != nil {
			err := cacheFile.StoreSelected(j.tag, tag)
			if err != nil {
				j.logger.Error("store selected: ", err)
			}
		}
	}
	j.interruptGroup.Interrupt(j.interruptExternalConnections)
	return true
}

func (j *JSTest) Now() string {
	return j.selected.Tag()
}

func (j *JSTest) All() []string {
	return j.tags
}

func (j *JSTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := j.selected.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return j.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (j *JSTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := j.selected.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return j.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (j *JSTest) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	return j.selected.NewConnection(ctx, conn, metadata)
}

func (j *JSTest) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	return j.selected.NewPacketConnection(ctx, conn, metadata)
}
