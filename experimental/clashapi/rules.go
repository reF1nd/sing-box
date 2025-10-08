package clashapi

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ruleRouter(router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules(router))
	r.Route("/{uuid}", func(r chi.Router) {
		r.Use(parseRuleUUID, findRuleByUUID(router))
		r.Put("/", changeRuleStatus)
	})
	return r
}

type Rule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`

	Disabled bool   `json:"disabled,omitempty"`
	UUID     string `json:"uuid,omitempty"`
}

func getRules(router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		rawRules := router.Rules()

		var rules []Rule
		for _, rule := range rawRules {
			rules = append(rules, Rule{
				Type:    rule.Type(),
				Payload: rule.String(),
				Proxy:   rule.Action().String(),

				Disabled: rule.Disabled(),
				UUID:     rule.UUID(),
			})
		}
		render.JSON(w, r, render.M{
			"rules": rules,
		})
	}
}

func parseRuleUUID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uuid := getEscapeParam(r, "uuid")
		ctx := context.WithValue(r.Context(), CtxKeyRuleUUID, uuid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findRuleByUUID(router adapter.Router) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uuid := r.Context().Value(CtxKeyRuleUUID).(string)
			routeRule, exist := router.Rule(uuid)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyRule, routeRule)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func changeRuleStatus(w http.ResponseWriter, r *http.Request) {
	rule := r.Context().Value(CtxKeyRule).(adapter.Rule)
	rule.ChangeStatus()
	render.NoContent(w, r)
}
