package route

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvaluateMultipleClashModes(t *testing.T) {
	modes := []string{"Rule", "Global"}
	require.Equal(t, staticMatchAlways, evaluateClashMode(modes, "global", false, false))
	require.Equal(t, staticMatchNever, evaluateClashMode(modes, "Direct", false, false))
	require.Equal(t, staticMatchUnknown, evaluateClashMode(modes, "Rule", false, true))
	require.Equal(t, staticMatchNever, evaluateClashMode(modes, "Global", true, false))
	require.Equal(t, staticMatchAlways, evaluateClashMode(modes, "Direct", true, true))
	require.Equal(t, staticMatchAlways, evaluateClashMode(nil, "Rule", false, false))
}
