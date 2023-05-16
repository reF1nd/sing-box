package option

type SideLoadOutboundOptions struct {
	DialerOptions
	Server          string           `json:"server,omitempty"`
	ServerPort      uint16           `json:"server_port,omitempty"`
	ListenPort      uint16           `json:"listen_port,omitempty"`
	ListenNetwork   NetworkList      `json:"listen_network,omitempty"`
	UDPTimeout      int64            `json:"udp_timeout,omitempty"`
	Command         Listable[string] `json:"command"`
	Env             Listable[string] `json:"env,omitempty"`
	Socks5ProxyPort uint16           `json:"socks5_proxy_port"`
	Network         NetworkList      `json:"network,omitempty"`
}
