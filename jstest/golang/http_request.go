package golang

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/robertkrimen/otto"
)

type HTTPRequest struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers"`
	Cookies         map[string]string `json:"cookies"`
	Body            string            `json:"body"`
	DisableRedirect bool              `json:"disable_redirect"`
	Timeout         option.Duration   `json:"timeout"`
	Detour          string            `json:"detour"`
}

type HTTPResponse struct {
	Status  int
	Headers map[string]string
	Body    string
	Cost    time.Duration
	Error   error
}

var HTTPRequestKey = (*struct{})(nil)

func JSGoHTTPRequests(ctx context.Context, jsVM *otto.Otto, httpClient *http.Client) func(call otto.FunctionCall) otto.Value {
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
		var requests []HTTPRequest
		err = json.Unmarshal(raw, &requests)
		if err != nil {
			return nil, E.Cause(err, "failed to parse requests")
		}
		for i := range requests {
			if requests[i].Method == "" {
				requests[i].Method = http.MethodGet
			}
			if requests[i].URL == "" {
				return nil, E.Cause(err, "url must not be empty")
			}
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

		ctx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, timeout)
		} else {
			ctx, cancel = context.WithCancel(ctx)
		}
		defer cancel()

		responses := make([]HTTPResponse, len(requests))
		var responseLock sync.Mutex
		if len(requests) == 1 {
			request := requests[0]
			ctx := context.WithValue(ctx, HTTPRequestKey, &request)
			responses[0] = *HTTPRequestDo(ctx, httpClient, &request)
		} else {
			requestDone := make(chan struct{}, len(requests))
			for i, request := range requests {
				go func(index int, request HTTPRequest) {
					defer func() {
						requestDone <- struct{}{}
					}()
					ctx := context.WithValue(ctx, HTTPRequestKey, &request)
					response := HTTPRequestDo(ctx, httpClient, &request)
					responseLock.Lock()
					responses[index] = *response
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
				responseJS.Set("cost", response.Cost.Milliseconds())
				responseJS.Set("status", response.Status)
				responseJS.Set("headers", response.Headers)
				responseJS.Set("body", response.Body)
			}
			responsesJS.Call("push", responseJS)
		}
		responseValue := responsesJS.Value()

		return &responseValue, nil
	})
}

func HTTPRequestDo(ctx context.Context, httpClient *http.Client, req *HTTPRequest) (resp *HTTPResponse) {
	resp = &HTTPResponse{}
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequest(req.Method, req.URL, body)
	if err != nil {
		resp.Error = E.Cause(err, "failed to create http request")
		return
	}
	if req.Headers != nil && len(req.Headers) > 0 {
		for k, v := range req.Headers {
			httpReq.Header.Set(k, v)
		}
	}
	if req.Cookies != nil && len(req.Cookies) > 0 {
		for key, value := range req.Cookies {
			httpReq.AddCookie(&http.Cookie{
				Name:  key,
				Value: value,
			})
		}
	}

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.Timeout))
		defer cancel()
	}

	t := time.Now()
	httpResp, err := httpClient.Do(httpReq.WithContext(ctx))
	if err != nil {
		resp.Error = E.Cause(err, "failed to do http request")
		return
	}
	resp.Cost = time.Since(t)

	resp.Status = httpResp.StatusCode
	buffer := bytes.NewBuffer(nil)
	_, err = io.Copy(buffer, httpResp.Body)
	if err != nil {
		resp.Error = E.Cause(err, "failed to read http response body")
		return
	}

	if buffer.Len() > 0 {
		resp.Body = buffer.String()
	}
	resp.Headers = make(map[string]string)
	for k, v := range httpResp.Header {
		resp.Headers[k] = strings.Join(v, ", ")
	}

	return
}
