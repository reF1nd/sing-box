package option

type JSTestOutboundOptions struct {
	Outbounds                 []string       `json:"outbounds"`
	JSPath                    string         `json:"js_path,omitempty"`
	JSBase64                  string         `json:"js_base64,omitempty"`
	JSGlobalVar               map[string]any `json:"js_global_var,omitempty"`
	Interval                  Duration       `json:"interval,omitempty"`
	InterruptExistConnections bool           `json:"interrupt_exist_connections,omitempty"`
}
