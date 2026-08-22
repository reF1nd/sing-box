package observability

import (
	"container/heap"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const topCacheTTL = 3 * time.Second

type connectionCursor struct {
	Timestamp time.Time `json:"t"`
	ID        string    `json:"i"`
}

func sortConnections(connections []Connection, closed bool) {
	sort.Slice(connections, func(i, j int) bool {
		left, right := connections[i].StartedAt, connections[j].StartedAt
		if closed {
			left, right = connections[i].ClosedAt, connections[j].ClosedAt
		}
		if left.Equal(right) {
			return connections[i].ID > connections[j].ID
		}
		return left.After(right)
	})
}

func paginateConnections(connections []Connection, cursorValue string, limit int, closed bool) (ConnectionPage, error) {
	if limit <= 0 {
		limit = 100
	}
	start := 0
	if cursorValue != "" {
		cursor, err := decodeConnectionCursor(cursorValue)
		if err != nil {
			return ConnectionPage{}, err
		}
		start = sort.Search(len(connections), func(index int) bool {
			timestamp := connections[index].StartedAt
			if closed {
				timestamp = connections[index].ClosedAt
			}
			return timestamp.Before(cursor.Timestamp) || timestamp.Equal(cursor.Timestamp) && connections[index].ID < cursor.ID
		})
	}
	end := min(start+limit, len(connections))
	page := ConnectionPage{Data: connections[start:end], Total: len(connections), HasMore: end < len(connections)}
	if page.HasMore && len(page.Data) > 0 {
		last := page.Data[len(page.Data)-1]
		timestamp := last.StartedAt
		if closed {
			timestamp = last.ClosedAt
		}
		page.NextCursor = encodeConnectionCursor(connectionCursor{Timestamp: timestamp, ID: last.ID})
	}
	return page, nil
}

func encodeConnectionCursor(cursor connectionCursor) string {
	content, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(content)
}

func decodeConnectionCursor(value string) (connectionCursor, error) {
	content, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return connectionCursor{}, errors.New("invalid cursor")
	}
	var cursor connectionCursor
	if json.Unmarshal(content, &cursor) != nil || cursor.Timestamp.IsZero() || cursor.ID == "" {
		return connectionCursor{}, errors.New("invalid cursor")
	}
	return cursor, nil
}

type topCacheKey struct {
	name       string
	window     time.Duration
	limit      int
	generation uint64
}

type topCacheEntry struct {
	createdAt time.Time
	page      DimensionPage
}

type dimensionHeap []Dimension

func (h dimensionHeap) Len() int           { return len(h) }
func (h dimensionHeap) Less(i, j int) bool { return dimensionWorse(h[i], h[j]) }
func (h dimensionHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *dimensionHeap) Push(value any)    { *h = append(*h, value.(Dimension)) }
func (h *dimensionHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

func pushTopDimension(result *dimensionHeap, value Dimension, limit int) {
	if result.Len() < limit {
		heap.Push(result, value)
		return
	}
	if dimensionBetter(value, (*result)[0]) {
		(*result)[0] = value
		heap.Fix(result, 0)
	}
}

func dimensionBetter(left, right Dimension) bool {
	leftBytes := left.Upload + left.Download
	rightBytes := right.Upload + right.Download
	return leftBytes > rightBytes || leftBytes == rightBytes && left.Value < right.Value
}

func dimensionWorse(left, right Dimension) bool {
	leftBytes := left.Upload + left.Download
	rightBytes := right.Upload + right.Download
	return leftBytes < rightBytes || leftBytes == rightBytes && left.Value > right.Value
}
