package dns

import (
	"testing"

	mDNS "github.com/miekg/dns"
)

func TestResolveRejectRcode(t *testing.T) {
	testCases := []struct {
		name         string
		actionRcode  int
		defaultRcode int
		expected     int
	}{
		{
			name:         "action overrides default",
			actionRcode:  mDNS.RcodeNameError,
			defaultRcode: mDNS.RcodeServerFailure,
			expected:     mDNS.RcodeNameError,
		},
		{
			name:         "default applies when action is unset",
			actionRcode:  -1,
			defaultRcode: mDNS.RcodeServerFailure,
			expected:     mDNS.RcodeServerFailure,
		},
		{
			name:         "refused applies when both are unset",
			actionRcode:  -1,
			defaultRcode: -1,
			expected:     mDNS.RcodeRefused,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := resolveRejectRcode(testCase.actionRcode, testCase.defaultRcode)
			if actual != testCase.expected {
				t.Fatalf("expected rcode %d, got %d", testCase.expected, actual)
			}
		})
	}
}
