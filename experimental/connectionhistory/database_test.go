//go:build with_connection_history

package connectionhistory

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestConnectionDeltaAndCloseRecord(t *testing.T) {
	database, err := openDatabase(context.Background(), filepath.Join(t.TempDir(), "history.db"))
	require.NoError(t, err)
	defer database.Close()

	manager := &Manager{
		database:       database,
		states:         make(map[string]*counterState),
		closed:         make(map[string]time.Time),
		pendingTraffic: make(map[aggregateKey]aggregate),
	}
	id, err := uuid.NewV4()
	require.NoError(t, err)
	upload := new(atomic.Int64)
	download := new(atomic.Int64)
	upload.Store(100)
	download.Store(50)
	startedAt := time.Now().Add(-time.Minute).UTC()
	metadata := trafficcontrol.TrackerMetadata{
		ID: id,
		Metadata: adapter.InboundContext{
			Network: "tcp",
			Source: M.Socksaddr{
				Addr: netip.MustParseAddr("192.0.2.10"),
				Port: 12345,
			},
			Destination: M.Socksaddr{
				Addr: netip.MustParseAddr("198.51.100.20"),
				Port: 443,
			},
			Domain: "example.com",
		},
		CreatedAt: startedAt,
		Upload:    upload,
		Download:  download,
		Outbound:  "proxy-a",
		Chain:     []string{"proxy-a", "selector"},
	}

	manager.processOpen(metadata)
	manager.processAt(metadata, false, startedAt.Add(30*time.Second))
	upload.Store(160)
	download.Store(80)
	metadata.ClosedAt = time.Now().UTC()
	manager.processAt(metadata, true, metadata.ClosedAt)
	require.NoError(t, manager.flush())

	query := Query{Start: startedAt.Add(-time.Minute), End: time.Now().Add(time.Minute)}
	summary, err := database.Summary(query)
	require.NoError(t, err)
	require.Equal(t, int64(160), summary.Upload)
	require.Equal(t, int64(80), summary.Download)
	require.Equal(t, int64(1), summary.Connections)

	connections, err := database.Connections(Query{
		Start:  query.Start,
		End:    query.End,
		Search: "example.com",
		Limit:  10,
	})
	require.NoError(t, err)
	require.Equal(t, 1, connections.Total)
	require.Equal(t, "proxy-a", connections.Data[0].Outbound)
	require.Equal(t, int64(160), connections.Data[0].Upload)

	domains, err := database.Dimensions("domains", query)
	require.NoError(t, err)
	require.Equal(t, 1, domains.Total)
	require.Equal(t, "example.com", domains.Data[0].Value)
	require.Equal(t, int64(240), domains.Data[0].Upload+domains.Data[0].Download)

	outbounds, err := database.Dimensions("outbounds", query)
	require.NoError(t, err)
	require.Equal(t, "proxy-a > selector", outbounds.Data[0].Value)
}

func TestDatabasePrune(t *testing.T) {
	database, err := openDatabase(context.Background(), filepath.Join(t.TempDir(), "history.db"))
	require.NoError(t, err)
	defer database.Close()

	now := time.Now().UTC()
	oldRecord := Record{ID: "old", ClosedAt: now.Add(-48 * time.Hour)}
	newRecord := Record{ID: "new", ClosedAt: now}
	oldBucket := now.Add(-48 * time.Hour).Truncate(time.Minute).Unix()
	newBucket := now.Truncate(time.Minute).Unix()
	oldHour := now.Add(-48 * time.Hour).Truncate(time.Hour).Unix()
	newHour := now.Truncate(time.Hour).Unix()
	updates := make(map[aggregateKey]aggregate)
	mergeAggregate(updates, aggregateKey{Bucket: oldBucket, Domain: "old.example"}, 1, 2, 1)
	mergeAggregate(updates, aggregateKey{Bucket: newBucket, Domain: "new.example"}, 3, 4, 1)
	mergeAggregate(updates, aggregateKey{Hour: true, Bucket: oldHour, Domain: "old.example"}, 1, 2, 1)
	mergeAggregate(updates, aggregateKey{Hour: true, Bucket: newHour, Domain: "new.example"}, 3, 4, 1)
	require.NoError(t, database.Write([]Record{oldRecord, newRecord}, updates))
	require.NoError(t, database.Prune(now.Add(-24*time.Hour)))

	page, err := database.Connections(Query{Start: now.Add(-72 * time.Hour), End: now.Add(time.Hour), Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, page.Total)
	require.Equal(t, "new", page.Data[0].ID)

	summary, err := database.Summary(Query{Start: now.Add(-72 * time.Hour), End: now.Add(time.Hour)})
	require.NoError(t, err)
	require.Equal(t, int64(3), summary.Upload)
	require.Equal(t, int64(4), summary.Download)
}
