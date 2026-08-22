package trafficcontrol

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

type testTracker struct {
	metadata TrackerMetadata
}

func (t *testTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *testTracker) Close() error {
	return nil
}

func TestClosedConnectionsLimit(t *testing.T) {
	manager := NewManager()
	manager.SetClosedConnectionsTTL(time.Hour)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, manager.Start(adapter.StartStateInitialize, scope))
	manager.SetClosedConnectionsLimit(2)

	ids := make([]uuid.UUID, 3)
	for i := range ids {
		ids[i] = uuid.Must(uuid.NewV4())
		tracker := &testTracker{metadata: TrackerMetadata{
			ID:       ids[i],
			Upload:   new(atomic.Int64),
			Download: new(atomic.Int64),
		}}
		tracker.metadata.Upload.Store(int64(i + 1))
		tracker.metadata.Download.Store(int64((i + 1) * 10))
		manager.join(tracker)
		manager.leave(tracker)
	}
	upload, download := manager.Total()
	require.Equal(t, int64(6), upload)
	require.Equal(t, int64(60), download)

	closed := manager.ClosedConnections()
	require.Len(t, closed, 2)
	require.Equal(t, ids[1], closed[0].ID)
	require.Equal(t, ids[2], closed[1].ID)

	manager.SetClosedConnectionsLimit(1)
	closed = manager.ClosedConnections()
	require.Len(t, closed, 1)
	require.Equal(t, ids[2], closed[0].ID)
	upload, download = manager.Total()
	require.Equal(t, int64(6), upload)
	require.Equal(t, int64(60), download)

	manager.SetClosedConnectionsLimit(0)
	require.Empty(t, manager.ClosedConnections())
	upload, download = manager.Total()
	require.Equal(t, int64(6), upload)
	require.Equal(t, int64(60), download)
}

func TestConnectionEvents(t *testing.T) {
	manager := NewManager()
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, manager.Start(adapter.StartStateInitialize, scope))
	subscription, _, err := manager.SubscribeEvents()
	require.NoError(t, err)
	defer manager.UnSubscribeEvents(subscription)

	tracker := &testTracker{metadata: TrackerMetadata{
		ID:       uuid.Must(uuid.NewV4()),
		Upload:   new(atomic.Int64),
		Download: new(atomic.Int64),
	}}
	manager.join(tracker)
	manager.leave(tracker)
	opened := <-subscription
	closed := <-subscription
	require.Equal(t, ConnectionEventNew, opened.Type)
	require.Equal(t, ConnectionEventClosed, closed.Type)
}

func TestClosedConnectionsTTLCleanup(t *testing.T) {
	manager := NewManager()
	manager.SetClosedConnectionsTTL(time.Hour)
	now := time.Unix(100000, 0)
	// Include out-of-order close times: concurrent leave calls can acquire the
	// history lock in a different order from when their timestamps were captured.
	ages := []time.Duration{2 * time.Hour, 30 * time.Minute, 90 * time.Minute, time.Hour}
	ids := make([]uuid.UUID, len(ages))
	for index, age := range ages {
		ids[index] = uuid.Must(uuid.NewV4())
		upload, download := new(atomic.Int64), new(atomic.Int64)
		upload.Store(int64(index + 1))
		download.Store(int64(index+1) * 10)
		manager.closedConnections.PushBack(TrackerMetadata{
			ID: ids[index], ClosedAt: now.Add(-age), Upload: upload, Download: download,
		})
	}
	manager.cleanupClosedConnectionsAt(now)
	retained := manager.ClosedConnections()
	require.Len(t, retained, 2)
	require.Equal(t, ids[1], retained[0].ID)
	require.Equal(t, ids[3], retained[1].ID)
	upload, download := manager.Total()
	require.Equal(t, int64(10), upload)
	require.Equal(t, int64(100), download)

	// Repeated cleanup must not double-count evicted traffic.
	manager.cleanupClosedConnectionsAt(now)
	manager.cleanupClosedConnectionsAt(now.Add(31 * time.Minute))
	require.Empty(t, manager.ClosedConnections())
	upload, download = manager.Total()
	require.Equal(t, int64(10), upload)
	require.Equal(t, int64(100), download)
}

func TestClosedConnectionsGCCleanupWithoutTTL(t *testing.T) {
	manager := NewManager()
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, manager.Start(adapter.StartStateInitialize, scope))
	tracker := &testTracker{metadata: TrackerMetadata{
		ID: uuid.Must(uuid.NewV4()), Upload: new(atomic.Int64), Download: new(atomic.Int64),
	}}
	tracker.metadata.Upload.Store(123)
	tracker.metadata.Download.Store(456)
	manager.join(tracker)
	manager.leave(tracker)
	runtime.GC()
	require.Eventually(t, func() bool { return len(manager.ClosedConnections()) == 0 }, time.Second, time.Millisecond)
	upload, download := manager.Total()
	require.Equal(t, int64(123), upload)
	require.Equal(t, int64(456), download)
}

func TestExplicitClearWithClosedConnectionsTTL(t *testing.T) {
	manager := NewManager()
	manager.SetClosedConnectionsTTL(time.Hour)
	upload, download := new(atomic.Int64), new(atomic.Int64)
	upload.Store(123)
	download.Store(456)
	manager.closedConnections.PushBack(TrackerMetadata{ClosedAt: time.Now(), Upload: upload, Download: download})
	manager.Clear()
	require.Empty(t, manager.ClosedConnections())
	totalUpload, totalDownload := manager.Total()
	require.Equal(t, int64(123), totalUpload)
	require.Equal(t, int64(456), totalDownload)
}
