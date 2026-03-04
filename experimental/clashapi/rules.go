package clashapi

import (
	"net/http"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ruleRouter(router adapter.Router, dnsRouter adapter.DNSRouter) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules(router, dnsRouter))
	return r
}

type Rule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
}

func getRules(router adapter.Router, dnsRouter adapter.DNSRouter) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var rules []Rule
		for _, rule := range dnsRouter.Rules() {
			rules = append(rules, Rule{
				Type:    rule.Type(),
				Payload: rule.String(),
				Proxy:   rule.Action().String(),
			})
		}
		for _, rule := range router.Rules() {
			rules = append(rules, Rule{
				Type:    rule.Type(),
				Payload: rule.String(),
				Proxy:   rule.Action().String(),
			})
		}
		render.JSON(w, r, render.M{
			"rules": rules,
		})
	}
}
