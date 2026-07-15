package libbox

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompareSemver(t *testing.T) {
	t.Parallel()

	require.False(t, CompareSemver("1.13.0-rc.4", "1.13.0"))
	require.True(t, CompareSemver("1.13.1", "1.13.0"))
	require.False(t, CompareSemver("v1.13.0", "1.13.0"))
	require.False(t, CompareSemver("1.13.0-", "1.13.0"))
	require.True(t, CompareSemver("1.14.0-alpha.46-reF1nd.1", "1.14.0-alpha.46-reF1nd"))
	require.False(t, CompareSemver("1.14.0-alpha.46-reF1nd", "1.14.0-alpha.46-reF1nd.1"))
	require.True(t, CompareSemver("1.14.0-alpha.47-reF1nd", "1.14.0-alpha.46-reF1nd.9"))
	require.True(t, CompareSemver("1.14.0-reF1nd.1", "1.14.0-reF1nd"))
}
