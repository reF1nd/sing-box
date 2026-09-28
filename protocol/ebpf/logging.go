//go:build with_ebpf && (linux || android)

package ebpf

import "encoding/json"

// ebpfStructuredEvent keeps eBPF lifecycle logs machine-readable without
// changing sing's logger interface. The logger still adds its normal timestamp
// and component prefix; the message body is a stable JSON object that can be
// indexed by event and fields without parsing a human-oriented sentence.
func ebpfStructuredEvent(event string, fields map[string]any) string {
	fields["event"] = event
	encoded, err := json.Marshal(fields)
	if err != nil {
		// All current fields are JSON-safe primitives. Keep a useful fallback if
		// a future field violates that contract rather than dropping the event.
		return `{"event":"` + event + `","encoding_error":true}`
	}
	return string(encoded)
}
