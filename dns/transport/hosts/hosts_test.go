package hosts

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestHosts(t *testing.T) {
	t.Parallel()
	require.Equal(t, []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()}, NewFile(context.Background(), "testdata/hosts").Lookup("localhost"))
	if runtime.GOOS != "windows" {
		defaultPathResolved, err := defaultPath()
		if err != nil {
			t.Fatal(E.Cause(err, "resolve default hosts path"))
		}
		content, readErr := os.ReadFile(defaultPathResolved)
		require.NoError(t, readErr)
		hFile := NewFile(context.Background(), defaultPathResolved)
		if len(hFile.Lookup("localhost")) == 0 {
			t.Fatal("failed to resolve localhost: ", defaultPathResolved, ": \n", string(content))
		}
	}
}

func TestPredefinedDomainResolvesLocalAliasChain(t *testing.T) {
	t.Parallel()
	transport := &Transport{
		predefined: map[string][]netip.Addr{
			"target.example.": {netip.MustParseAddr("192.0.2.1")},
		},
		predefinedDomain: map[string]string{
			"source.example.": "middle.example.",
			"middle.example.": "target.example.",
		},
	}
	message := &mDNS.Msg{
		Question: []mDNS.Question{{
			Name:   "source.example.",
			Qtype:  mDNS.TypeA,
			Qclass: mDNS.ClassINET,
		}},
	}
	response, err := transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
	require.Len(t, response.Answer, 1)
	record, isA := response.Answer[0].(*mDNS.A)
	require.True(t, isA)
	require.Equal(t, "source.example.", record.Hdr.Name)
	require.Equal(t, "192.0.2.1", record.A.String())
}

func TestPredefinedDomainRejectsLocalAliasLoop(t *testing.T) {
	t.Parallel()
	transport := &Transport{
		predefined: make(map[string][]netip.Addr),
		predefinedDomain: map[string]string{
			"source.example.": "target.example.",
			"target.example.": "source.example.",
		},
	}
	message := &mDNS.Msg{
		Question: []mDNS.Question{{
			Name:   "source.example.",
			Qtype:  mDNS.TypeA,
			Qclass: mDNS.ClassINET,
		}},
	}
	response, err := transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeServerFailure, response.Rcode)
}
