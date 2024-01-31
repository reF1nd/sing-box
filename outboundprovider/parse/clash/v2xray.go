package clash

type ClashTransportWebsocket struct {
	Path                string            `yaml:"path"`
	Headers             map[string]string `yaml:"headers"`
	MaxEarlyData        int               `yaml:"max-early-data"`
	EarlyDataHeaderName string            `yaml:"early-data-header-name"`
}

type ClashTransportGRPC struct {
	ServiceName string `yaml:"grpc-service-name"`
}

type ClashTransportHTTP struct {
	Method  string              `yaml:"method"`
	Path    []string            `yaml:"path"`
	Headers map[string][]string `yaml:"headers"`
}

type ClashTransportHTTP2 struct {
	Host []string `yaml:"host"`
	Path string   `yaml:"path"`
}

type ClashTransportReality struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}
