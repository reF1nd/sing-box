package golang

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/robertkrimen/otto"
)

type URLTestRequest struct {
	URL    string `json:"url"`
	Detour string `json:"detour"`
}

type URLTestResponse struct {
	Delay uint16
	Error error
}

func JSGoURLTest(ctx context.Context, router adapter.Router, jsVM *otto.Otto) func(otto.FunctionCall) otto.Value {
	return JSDo[otto.Value](jsVM, func(call otto.FunctionCall) (*otto.Value, error) {
		requestsArg := call.Argument(0)
		if !requestsArg.IsObject() {
			return nil, E.New("requests must be object")
		}

		requestsAny, err := requestsArg.Export()
		if err != nil {
			return nil, E.Cause(err, "failed to parse requests")
		}
		raw, err := json.Marshal(requestsAny)
		if err != nil {
			return nil, E.Cause(err, "failed to parse requests")
		}
		var requests []URLTestRequest
		err = json.Unmarshal(raw, &requests)
		if err != nil {
			return nil, E.Cause(err, "failed to parse requests")
		}
		for i := range requests {
			if requests[i].Detour == "" {
				return nil, E.Cause(err, "detour must not be empty")
			}
		}
		if len(requests) == 0 {
			return nil, E.Cause(err, "requests must not be empty")
		}

		var timeout time.Duration
		timeoutArg := call.Argument(1)
		if !timeoutArg.IsUndefined() {
			if timeoutArg.IsNumber() {
				n, _ := timeoutArg.ToInteger()
				timeout = time.Duration(n) * time.Second
			} else if timeoutArg.IsString() {
				s, _ := timeoutArg.ToString()
				if s != "" {
					d, err := time.ParseDuration(s)
					if err != nil {
						return nil, E.Cause(err, "failed to parse timeout")
					}
					timeout = d
				}
			} else {
				return nil, E.New("timeout must be number or string")
			}
		}

		var historyStorage *urltest.HistoryStorage
		clashServer := router.ClashServer()
		if clashServer != nil {
			historyStorage = clashServer.HistoryStorage()
		}

		ctx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, timeout)
		} else {
			ctx, cancel = context.WithCancel(ctx)
		}
		defer cancel()

		responses := make([]URLTestResponse, len(requests))
		var responseLock sync.Mutex
		if len(requests) == 1 {
			request := requests[0]
			dialer, loaded := router.Outbound(request.Detour)
			if !loaded {
				return nil, E.New("detour not found")
			}
			delay, err := urltest.URLTest(ctx, request.URL, dialer)
			if err != nil {
				if historyStorage != nil {
					historyStorage.DeleteURLTestHistory(request.Detour)
				}
				return nil, E.Cause(err, "urltest failed")
			}
			historyStorage.StoreURLTestHistory(request.Detour, &urltest.History{
				Time:  time.Now(),
				Delay: delay,
			})
			responses[0] = URLTestResponse{
				Delay: delay,
			}
		} else {
			requestDone := make(chan struct{}, len(requests))
			for i, request := range requests {
				go func(index int, request URLTestRequest) {
					defer func() {
						requestDone <- struct{}{}
					}()
					var response URLTestResponse
					dialer, loaded := router.Outbound(request.Detour)
					if !loaded {
						response.Error = E.New("detour not found")
					} else {
						delay, err := urltest.URLTest(ctx, request.URL, dialer)
						if err != nil {
							response.Error = E.Cause(err, "urltest failed")
							if historyStorage != nil {
								historyStorage.DeleteURLTestHistory(request.Detour)
							}
						} else {
							response.Delay = delay
							if historyStorage != nil {
								historyStorage.StoreURLTestHistory(request.Detour, &urltest.History{
									Time:  time.Now(),
									Delay: delay,
								})
							}
						}
					}
					responseLock.Lock()
					responses[index] = response
					responseLock.Unlock()
				}(i, request)
			}
			for i := 0; i < len(requests); i++ {
				<-requestDone
			}
		}

		responsesJS, _ := jsVM.Object(`(new Array())`)
		for _, response := range responses {
			responseJS, _ := jsVM.Object(`({})`)
			if response.Error != nil {
				responseJS.Set("error", response.Error.Error())
			} else {
				responseJS.Set("delay", response.Delay)
			}
			responsesJS.Call("push", responseJS)
		}
		responseValue := responsesJS.Value()

		return &responseValue, nil
	})
}
