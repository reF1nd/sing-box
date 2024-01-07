package option

type RedirectInboundOptions struct {
	ListenOptions
	Scripts Listable[ScriptOptions] `json:"scripts,omitempty"`
}

type TProxyInboundOptions struct {
	ListenOptions
	Network NetworkList             `json:"network,omitempty"`
	Scripts Listable[ScriptOptions] `json:"scripts,omitempty"`
}
