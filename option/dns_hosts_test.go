package option

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/json"
)

func TestHostsPredefinedValueReuse(t *testing.T) {
	var value HostsDNSPredefinedValue
	for _, input := range []string{`"alias.example"`, `"192.0.2.1"`, `"alias.example"`, `["192.0.2.1"]`} {
		if err := json.Unmarshal([]byte(input), &value); err != nil {
			t.Fatal(err)
		}
		if input == `"alias.example"` {
			if value.Domain != "alias.example" || len(value.Addresses) != 0 {
				t.Fatalf("stale address in alias: %+v", value)
			}
		} else if value.Domain != "" || len(value.Addresses) != 1 || value.Addresses[0] != netip.MustParseAddr("192.0.2.1") {
			t.Fatalf("stale alias in address value: %+v", value)
		}
	}
}
