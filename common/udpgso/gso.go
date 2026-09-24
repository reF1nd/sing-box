package udpgso

import (
	"os"
	"strconv"
)

// A process-wide prohibition takes precedence over per-listener/dialer options.
var disabled, _ = strconv.ParseBool(os.Getenv("SING_BOX_DISABLE_GSO"))

func Disabled(enabled *bool) bool {
	return disabled || enabled != nil && !*enabled
}
