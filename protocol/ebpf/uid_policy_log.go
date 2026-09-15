//go:build with_ebpf && (linux || android)

package ebpf

import (
	"strconv"
	"strings"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func formatUIDRanges(ranges []commonEBPF.UIDRange) string {
	if len(ranges) == 0 {
		return "[]"
	}
	var builder strings.Builder
	builder.WriteByte('[')
	for index, uidRange := range ranges {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(strconv.FormatUint(uint64(uidRange.Start), 10))
		if uidRange.Start != uidRange.End {
			builder.WriteByte('-')
			builder.WriteString(strconv.FormatUint(uint64(uidRange.End), 10))
		}
	}
	builder.WriteByte(']')
	return builder.String()
}
