package option

import (
	"fmt"

	"github.com/sagernet/sing/common/json"
)

// TCPCongestionControl selects the internal Go TCP sender's congestion controller.
// The zero value preserves the stack default; explicit JSON values must be nonempty.
type TCPCongestionControl string

const (
	TCPCongestionReno  TCPCongestionControl = "reno"
	TCPCongestionCubic TCPCongestionControl = "cubic"
	TCPCongestionBBR   TCPCongestionControl = "bbr"
)

func (c *TCPCongestionControl) UnmarshalJSON(content []byte) error {
	var value string
	if err := json.Unmarshal(content, &value); err != nil {
		return fmt.Errorf("tcp_congestion_control: %w", err)
	}
	if value == "" {
		return fmt.Errorf("tcp_congestion_control must be a nonempty algorithm name")
	}
	parsed := TCPCongestionControl(value)
	if err := parsed.Validate(); err != nil {
		return err
	}
	*c = parsed
	return nil
}

func (c TCPCongestionControl) Validate() error {
	switch c {
	case "", TCPCongestionReno, TCPCongestionCubic, TCPCongestionBBR:
		return nil
	default:
		return fmt.Errorf("unknown tcp_congestion_control: %q", c)
	}
}
