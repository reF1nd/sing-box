package dns

import (
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

func TestRulesSnapshotConcurrentClose(t *testing.T) {
	router := &Router{rules: []adapter.DNSRule{}}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				_ = router.Rules()
			}
		})
	}
	require.NoError(t, router.Close())
	workers.Wait()
	require.Empty(t, router.Rules())
}
