package option

type RandomAddrOutboundOptions struct {
	Addresses  Listable[RandomAddress] `json:"addresses,omitempty"`
	IgnoreFqdn bool                    `json:"ignore_fqdn,omitempty"`
	DeleteFqdn bool                    `json:"delete_fqdn,omitempty"`
	UDP        bool                    `json:"udp,omitempty"`
	DialerOptions
}

type RandomAddress struct {
	IP   string `json:"ip,omitempty"`
	Port uint16 `json:"port,omitempty"`
}
