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

func TestDNSRejectResponsePackRoundTrip(t *testing.T) {
	makeQuery := func(withEDNS bool, doBit bool) *mDNS.Msg {
		query := &mDNS.Msg{
			MsgHdr: mDNS.MsgHdr{Id: 0x4242},
			Question: []mDNS.Question{{
				Name:   "blocked.example.",
				Qtype:  mDNS.TypeA,
				Qclass: mDNS.ClassINET,
			}},
		}
		if withEDNS {
			query.SetEdns0(1232, doBit)
		}
		return query
	}
	for _, tc := range []struct {
		name      string
		queryEDNS bool
		queryDO   bool
		rcode     int
		wantRcode int
		wantEDNS  bool
		wantDO    bool
	}{
		{name: "no_edns_noerror", queryEDNS: false, rcode: mDNS.RcodeSuccess, wantRcode: mDNS.RcodeSuccess, wantEDNS: false},
		{name: "no_edns_nxdomain", queryEDNS: false, rcode: mDNS.RcodeNameError, wantRcode: mDNS.RcodeNameError, wantEDNS: false},
		{name: "no_edns_refused", queryEDNS: false, rcode: mDNS.RcodeRefused, wantRcode: mDNS.RcodeRefused, wantEDNS: false},
		{name: "no_edns_badvers_fallback", queryEDNS: false, rcode: mDNS.RcodeBadVers, wantRcode: mDNS.RcodeRefused, wantEDNS: false},
		{name: "no_edns_badcookie_fallback", queryEDNS: false, rcode: mDNS.RcodeBadCookie, wantRcode: mDNS.RcodeRefused, wantEDNS: false},
		{name: "no_edns_max_extended_fallback", queryEDNS: false, rcode: 0xFFF, wantRcode: mDNS.RcodeRefused, wantEDNS: false},
		{name: "edns_noerror", queryEDNS: true, rcode: mDNS.RcodeSuccess, wantRcode: mDNS.RcodeSuccess, wantEDNS: true},
		{name: "edns_nxdomain", queryEDNS: true, rcode: mDNS.RcodeNameError, wantRcode: mDNS.RcodeNameError, wantEDNS: true},
		{name: "edns_refused", queryEDNS: true, rcode: mDNS.RcodeRefused, wantRcode: mDNS.RcodeRefused, wantEDNS: true},
		{name: "edns_do_refused", queryEDNS: true, queryDO: true, rcode: mDNS.RcodeRefused, wantRcode: mDNS.RcodeRefused, wantEDNS: true, wantDO: true},
		{name: "edns_badvers", queryEDNS: true, rcode: mDNS.RcodeBadVers, wantRcode: mDNS.RcodeBadVers, wantEDNS: true},
		{name: "edns_do_badcookie", queryEDNS: true, queryDO: true, rcode: mDNS.RcodeBadCookie, wantRcode: mDNS.RcodeBadCookie, wantEDNS: true, wantDO: true},
		{name: "edns_max_extended", queryEDNS: true, rcode: 0xFFF, wantRcode: 0xFFF, wantEDNS: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := dnsRejectResponse(makeQuery(tc.queryEDNS, tc.queryDO), tc.rcode, -1)
			raw, err := resp.Pack()
			if err != nil {
				t.Fatalf("Pack failed for rcode %d: %v", tc.rcode, err)
			}
			var unpacked mDNS.Msg
			if err := unpacked.Unpack(raw); err != nil {
				t.Fatalf("Unpack failed for rcode %d: %v", tc.rcode, err)
			}
			if unpacked.Rcode != tc.wantRcode {
				t.Fatalf("unpacked rcode = %d, want %d", unpacked.Rcode, tc.wantRcode)
			}
			opt := unpacked.IsEdns0()
			hasOPT := opt != nil
			if hasOPT != tc.wantEDNS {
				t.Fatalf("EDNS0 OPT presence = %v, want %v", hasOPT, tc.wantEDNS)
			}
			if hasOPT && opt.Do() != tc.wantDO {
				t.Fatalf("EDNS0 DO bit = %v, want %v", opt.Do(), tc.wantDO)
			}
		})
	}
}
