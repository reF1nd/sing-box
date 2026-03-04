package dns

import (
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestRulesSnapshotConcurrentClose(t *testing.T) {
	logger := log.NewNOPFactory()
	scope := adapter.NewScope(t.Context(), logger.Logger())
	t.Cleanup(func() { _ = scope.Close() })
	router, err := NewRouter(scope.Context(), logger, option.DNSOptions{})
	require.NoError(t, err)
	require.NoError(t, router.Start(adapter.StartStateStart, scope))
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				_ = router.Rules()
			}
		})
	}
	require.NoError(t, scope.Close())
	workers.Wait()
	require.Empty(t, router.Rules())
}
