package utils

import (
	"fmt"
	"regexp"
	"strconv"
)

func StringToMbps(s string) uint64 {
	if s == "" {
		return 0
	}

	// when have not unit, use Mbps
	if v, err := strconv.Atoi(s); err == nil {
		return StringToMbps(fmt.Sprintf("%d Mbps", v))
	}

	m := regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`).FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	var n uint64
	switch m[2] {
	case "K":
		n = 1 >> 10
	case "M":
		n = 1
	case "G":
		n = 1 << 10
	case "T":
		n = 1 << 20
	default:
		n = 1
	}
	v, _ := strconv.ParseUint(m[1], 10, 64)
	n = v * n
	if m[3] == "B" {
		n = n << 3
	}
	return n
}
