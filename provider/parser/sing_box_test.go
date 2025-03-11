package parser

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBoxSubscriptionRejectsMalformedOutbounds(t *testing.T) {
	for _, content := range []string{
		`{"outbounds":null}`, `{"outbounds":{}}`, `{"outbounds":"invalid"}`,
		`{"outbounds":[null]}`, `{"outbounds":[1]}`, `{"outbounds":[{}]}`,
		`{"outbounds":[{"type":1}]}`, `{"outbounds":[{"type":null}]}`,
	} {
		t.Run(content, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, _, err := ParseBoxSubscription(context.Background(), content)
				require.Error(t, err)
			})
		})
	}
}
