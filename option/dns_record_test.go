package option

import (
	"context"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func mustRecordOptions(t *testing.T, record string) DNSRecordOptions {
	t.Helper()
	var value DNSRecordOptions
	require.NoError(t, value.UnmarshalJSON([]byte(`"`+record+`"`)))
	return value
}

func TestDNSRecordOptionsUnmarshalJSONRejectsRelativeNames(t *testing.T) {
	t.Parallel()

	for _, record := range []string{
		"@ IN A 1.1.1.1",
		"www IN CNAME example.com.",
		"example.com. IN CNAME @",
		"example.com. IN CNAME www",
	} {
		var value DNSRecordOptions
		err := value.UnmarshalJSON([]byte(`"` + record + `"`))
		require.Error(t, err)
	}
}

func TestDNSRecordOptionsMatchIgnoresTTL(t *testing.T) {
	t.Parallel()

	expected := mustRecordOptions(t, "example.com. 600 IN A 1.1.1.1")
	record, err := dns.NewRR("example.com. 60 IN A 1.1.1.1")
	require.NoError(t, err)

	require.True(t, expected.Match(record))
}

func TestDNSRejectRCodeUnmarshalValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input string
		want  int
	}{
		{input: `""`, want: -1},
		{input: `-1`, want: -1},
		{input: `0`, want: dns.RcodeSuccess},
		{input: `"NOERROR"`, want: dns.RcodeSuccess},
		{input: `"BADCOOKIE"`, want: dns.RcodeBadCookie},
		{input: `4095`, want: 0xFFF},
	} {
		var r DNSRejectRCode
		require.NoError(t, json.Unmarshal([]byte(tc.input), &r), tc.input)
		require.Equal(t, tc.want, r.Build(), tc.input)
	}
	for _, invalid := range []string{`-2`, `4096`, `"NO_SUCH_RCODE"`} {
		var r DNSRejectRCode
		require.Error(t, json.Unmarshal([]byte(invalid), &r), invalid)
	}
}

func TestDNSRejectRCodeSchemaBounds(t *testing.T) {
	t.Parallel()

	content, err := schema.Generate(context.Background(), reflect.TypeFor[DNSRejectRCode]())
	require.NoError(t, err)
	var root struct {
		Defs map[string]struct {
			AnyOf []struct {
				Type    string  `json:"type"`
				Minimum *int64  `json:"minimum"`
				Maximum *uint64 `json:"maximum"`
			} `json:"anyOf"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(content, &root))
	def, ok := root.Defs["DNSRejectRCode"]
	require.True(t, ok)
	require.NotEmpty(t, def.AnyOf)
	require.Equal(t, "integer", def.AnyOf[0].Type)
	require.NotNil(t, def.AnyOf[0].Minimum)
	require.Equal(t, int64(-1), *def.AnyOf[0].Minimum)
	require.NotNil(t, def.AnyOf[0].Maximum)
	require.Equal(t, uint64(0xFFF), *def.AnyOf[0].Maximum)
}
