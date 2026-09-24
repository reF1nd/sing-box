package udpgso

import "testing"

func TestGlobalProhibition(t *testing.T) {
	enabledTrue, enabledFalse := true, false
	previous := disabled
	defer func() { disabled = previous }()
	for _, global := range []bool{false, true} {
		disabled = global
		for _, enabled := range []*bool{nil, &enabledTrue, &enabledFalse} {
			want := global || enabled != nil && !*enabled
			if Disabled(enabled) != want {
				t.Fatal("incorrect policy precedence")
			}
		}
	}
}
