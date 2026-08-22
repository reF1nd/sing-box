package trafficcontrol

import (
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"

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
	manager := NewManager(nil)
	require.NoError(t, manager.Start(adapter.StartStateInitialize))
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
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
	manager := NewManager(nil)
	require.NoError(t, manager.Start(adapter.StartStateInitialize))
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
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
