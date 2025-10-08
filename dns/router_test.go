package dns

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"

	mDNS "github.com/miekg/dns"
)

type legacyAliasRule struct {
	action              adapter.RuleAction
	matchCount          int
	legacyPreMatchCount int
}

func (r *legacyAliasRule) Match(*adapter.InboundContext) bool {
	r.matchCount++
	return true
}

func (r *legacyAliasRule) RuleCount() uint64 {
	return 1
}

func (r *legacyAliasRule) String() string {
	return ""
}

func (r *legacyAliasRule) Start() error {
	return nil
}

func (r *legacyAliasRule) Close() error {
	return nil
}

func (r *legacyAliasRule) Disabled() bool {
	return false
}

func (r *legacyAliasRule) UUID() string {
	return ""
}

func (r *legacyAliasRule) ChangeStatus() {
}

func (r *legacyAliasRule) Type() string {
	return C.RuleTypeDefault
}

func (r *legacyAliasRule) Action() adapter.RuleAction {
	return r.action
}

func (r *legacyAliasRule) LegacyPreMatch(*adapter.InboundContext) bool {
	r.legacyPreMatchCount++
	return true
}

func (r *legacyAliasRule) WithAddressLimit() bool {
	return false
}

func (r *legacyAliasRule) MatchAddressLimit(*adapter.InboundContext, *mDNS.Msg) bool {
	return true
}

func (r *legacyAliasRule) MatchResponseTag() string {
	return ""
}

func (r *legacyAliasRule) MatchResponseTags() []string {
	return nil
}

func (r *legacyAliasRule) MatchResponseAnonymous() bool {
	return false
}

func (r *legacyAliasRule) Race() bool {
	return false
}

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

func TestFindLastCNAMETarget(t *testing.T) {
	const (
		source = "source.example."
		target = "target.example."
	)
	cname := func(owner string, destination string) mDNS.RR {
		return &mDNS.CNAME{
			Hdr: mDNS.RR_Header{
				Name:   owner,
				Rrtype: mDNS.TypeCNAME,
				Class:  mDNS.ClassINET,
			},
			Target: destination,
		}
	}
	address4 := func(owner string) mDNS.RR {
		return &mDNS.A{
			Hdr: mDNS.RR_Header{
				Name:   owner,
				Rrtype: mDNS.TypeA,
				Class:  mDNS.ClassINET,
			},
			A: net.IPv4(192, 0, 2, 1),
		}
	}
	address6 := func(owner string) mDNS.RR {
		return &mDNS.AAAA{
			Hdr: mDNS.RR_Header{
				Name:   owner,
				Rrtype: mDNS.TypeAAAA,
				Class:  mDNS.ClassINET,
			},
			AAAA: net.ParseIP("2001:db8::1"),
		}
	}
	testCases := []struct {
		name     string
		query    string
		records  []mDNS.RR
		qType    uint16
		expected string
	}{
		{
			name:     "canonicalizes names",
			query:    "SOURCE.EXAMPLE.",
			records:  []mDNS.RR{cname(source, "TARGET.EXAMPLE.")},
			qType:    mDNS.TypeA,
			expected: target,
		},
		{
			name:     "A query ignores terminal AAAA",
			query:    source,
			records:  []mDNS.RR{cname(source, target), address6(target)},
			qType:    mDNS.TypeA,
			expected: target,
		},
		{
			name:    "A query stops at terminal A",
			query:   source,
			records: []mDNS.RR{cname(source, target), address4(target)},
			qType:   mDNS.TypeA,
		},
		{
			name:     "AAAA query ignores terminal A",
			query:    source,
			records:  []mDNS.RR{cname(source, target), address4(target)},
			qType:    mDNS.TypeAAAA,
			expected: target,
		},
		{
			name:    "unspecified query type accepts either address family",
			query:   source,
			records: []mDNS.RR{cname(source, target), address6(target)},
		},
		{
			name:    "detects case-insensitive loop",
			query:   source,
			records: []mDNS.RR{cname(source, "TARGET.EXAMPLE."), cname(target, "SOURCE.EXAMPLE.")},
			qType:   mDNS.TypeA,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := findLastCNAMETarget(testCase.query, testCase.records, testCase.qType)
			if actual != testCase.expected {
				t.Fatalf("expected target %q, got %q", testCase.expected, actual)
			}
		})
	}
}

func TestContextWithAliasResolutionCanonicalizesNames(t *testing.T) {
	ctx, loopDetected := ContextWithAliasResolution(context.Background(), "SOURCE.EXAMPLE.", "TARGET.EXAMPLE.")
	if loopDetected {
		t.Fatal("unexpected loop in initial alias")
	}
	_, loopDetected = ContextWithAliasResolution(ctx, "target.example.", "source.example.")
	if !loopDetected {
		t.Fatal("expected case-insensitive alias loop")
	}
}

func TestFollowPredefinedCNAMEUsesLegacyRuleEngine(t *testing.T) {
	const (
		source = "source.example."
		target = "target.example."
	)
	rule := &legacyAliasRule{
		action: &R.RuleActionPredefined{
			Rcode: mDNS.RcodeSuccess,
			Answer: []mDNS.RR{&mDNS.A{
				Hdr: mDNS.RR_Header{
					Name:   target,
					Rrtype: mDNS.TypeA,
					Class:  mDNS.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(192, 0, 2, 1),
			}},
		},
	}
	router := &Router{
		logger:        log.NewNOPFactory().NewLogger("dns"),
		rules:         []adapter.DNSRule{rule},
		legacyDNSMode: true,
	}
	query := &mDNS.Msg{
		Question: []mDNS.Question{{
			Name:   source,
			Qtype:  mDNS.TypeA,
			Qclass: mDNS.ClassINET,
		}},
	}
	response := &mDNS.Msg{
		MsgHdr:   mDNS.MsgHdr{Response: true},
		Question: query.Question,
		Answer: []mDNS.RR{&mDNS.CNAME{
			Hdr: mDNS.RR_Header{
				Name:   source,
				Rrtype: mDNS.TypeCNAME,
				Class:  mDNS.ClassINET,
				Ttl:    60,
			},
			Target: target,
		}},
	}

	resolved := router.followPredefinedCNAME(context.Background(), query, response, adapter.DNSQueryOptions{})
	if len(resolved.Answer) != 2 {
		t.Fatalf("expected CNAME and resolved address, got %d answers", len(resolved.Answer))
	}
	if _, isAddress := resolved.Answer[1].(*mDNS.A); !isAddress {
		t.Fatalf("expected resolved A record, got %T", resolved.Answer[1])
	}
	if rule.legacyPreMatchCount != 1 {
		t.Fatalf("expected one legacy pre-match, got %d", rule.legacyPreMatchCount)
	}
	if rule.matchCount != 0 {
		t.Fatalf("expected modern match path to be skipped, got %d calls", rule.matchCount)
	}
}
