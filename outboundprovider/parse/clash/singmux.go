package clash

type ClashSingMuxOptions struct {
	Enabled        bool   `yaml:"enabled,omitempty"`
	Protocol       string `yaml:"protocol,omitempty"`
	MaxConnections int    `yaml:"max-connections,omitempty"`
	MinStreams     int    `yaml:"min-streams,omitempty"`
	MaxStreams     int    `yaml:"max-streams,omitempty"`
	Padding        bool   `yaml:"padding,omitempty"`
}
