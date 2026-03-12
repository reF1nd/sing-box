package option

import (
	"context"
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestMASQUEInnerResolverJSON(t *testing.T) {
	for _, value := range []string{`"inner"`, `{"server":"inner","disable_cache":true,"timeout":"2s"}`} {
		for _, options := range []InnerDomainResolverOptionsWrapper{new(MASQUEClientEndpointOptions), new(MASQUEServerEndpointOptions)} {
			content := []byte(`{"inner_domain_resolver":` + value + `}`)
			require.NoError(t, json.UnmarshalContext(context.Background(), content, options))
			var expected DomainResolveOptions
			require.NoError(t, json.Unmarshal([]byte(value), &expected))
			require.Equal(t, &expected, options.TakeInnerDomainResolverOptions())
			encoded, err := json.Marshal(options)
			require.NoError(t, err)
			require.NoError(t, json.UnmarshalContext(context.Background(), encoded, options))
			require.Equal(t, &expected, options.TakeInnerDomainResolverOptions())
		}
	}
}
