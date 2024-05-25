package clashapi

var (
	CtxKeyProxyName    = contextKey("proxy name")
	CtxKeyProviderName = contextKey("provider name")
	CtxKeyRuleUUID     = contextKey("rule uuid")
	CtxKeyProxy        = contextKey("proxy")
	CtxKeyProvider     = contextKey("provider")
	CtxKeyRule         = contextKey("rule")
)

type contextKey string

func (c contextKey) String() string {
	return "clash context key " + string(c)
}
