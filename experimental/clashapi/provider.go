package clashapi

import (
	"context"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/batch"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func proxyProviderRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProviders(server))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProviderName, findProviderByName(server))
		r.Get("/", getProvider)
		r.Put("/", updateProvider)
		r.Get("/healthcheck", checkProvider(server))
	})
	return r
}

func getProviders(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var responseMap, providersMap badjson.JSONObject
		for _, provider := range server.provider.Providers() {
			providersMap.Put(provider.Tag(), providerInfo(server, provider))
		}
		if providersMap.IsEmpty() {
			// fix Yacd-meta
			responseMap.Put("providers", render.M{})
		} else {
			responseMap.Put("providers", &providersMap)
		}
		response, err := responseMap.MarshalJSON()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Write(response)
	}
}

func getProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
	render.JSON(w, r, provider)
}

func providerInfo(server *Server, p adapter.Provider) *badjson.JSONObject {
	var info badjson.JSONObject
	proxies := make([]*badjson.JSONObject, 0)
	for _, detour := range p.Outbounds() {
		proxies = append(proxies, proxyInfo(server, detour))
	}
	info.Put("type", "Proxy")                                // Proxy, Rule
	info.Put("vehicleType", C.ProviderDisplayName(p.Type())) // HTTP, File, Compatible
	info.Put("name", p.Tag())
	info.Put("proxies", proxies)
	if p, ok := p.(adapter.ProviderRemote); ok {
		info.Put("updatedAt", p.UpdatedAt())
	}
	if p, ok := p.(adapter.ProviderInfoer); ok {
		info.Put("subscriptionInfo", p.Info())
	}
	return &info
}

func updateProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
	if provider, ok := provider.(adapter.ProviderRemote); ok {
		if err := provider.Update(); err != nil {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}
	render.NoContent(w, r)
}

func checkProvider(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		checked := make(map[string]bool)
		provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
		b2, _ := batch.New(context.Background(), batch.WithConcurrencyNum[any](10))
		for _, proxy := range provider.Outbounds() {
			realTag := adapter.OutboundTag(proxy)
			if checked[realTag] {
				continue
			}
			p, loaded := server.outbound.Outbound(realTag)
			if !loaded {
				continue
			}
			b2.Go(realTag, func() (any, error) {
				delay, err := urltest.URLTest(r.Context(), "", p)
				tag := realTag
				if err != nil {
					server.urlTestHistory.StoreURLTestHistory(tag, &urltest.History{
						Time:  time.Now(),
						Delay: 0,
					})
				} else {
					server.urlTestHistory.StoreURLTestHistory(tag, &urltest.History{
						Time:  time.Now(),
						Delay: delay,
					})
				}
				return nil, nil
			})
		}
		b2.Wait()
		render.NoContent(w, r)
	}
}

func parseProviderName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProviderName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProviderByName(server *Server) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProviderName).(string)
			provider, exist := server.provider.Provider(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}

			ctx := context.WithValue(r.Context(), CtxKeyProvider, provider)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
