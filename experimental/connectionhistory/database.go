//go:build with_connection_history

package connectionhistory

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing/service/filemanager"
)

var (
	bucketConnections = []byte("connections")
	bucketMinutes     = []byte("minutes")
	bucketHours       = []byte("hours")
)

type aggregate struct {
	Bucket      int64  `json:"t"`
	Domain      string `json:"d,omitempty"`
	IP          string `json:"i,omitempty"`
	Source      string `json:"s,omitempty"`
	Outbound    string `json:"o,omitempty"`
	Rule        string `json:"r,omitempty"`
	Upload      int64  `json:"u"`
	Download    int64  `json:"n"`
	Connections int64  `json:"c"`
}

type aggregateKey struct {
	Hour     bool
	Bucket   int64
	Domain   string
	IP       string
	Source   string
	Outbound string
	Rule     string
}

type database struct {
	path string
	db   *bbolt.DB
}

func openDatabase(ctx context.Context, path string) (*database, error) {
	const fileMode = 0o666
	file, err := filemanager.OpenFile(ctx, path, os.O_RDWR|os.O_CREATE, fileMode)
	if err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	db, err := bbolt.Open(path, fileMode, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	if err = filemanager.Chown(ctx, path); err != nil {
		db.Close()
		return nil, err
	}
	storage := &database{path: path, db: db}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, name := range [][]byte{bucketConnections, bucketMinutes, bucketHours} {
			if _, createErr := tx.CreateBucketIfNotExists(name); createErr != nil {
				return createErr
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return storage, nil
}

func (d *database) Close() error {
	return d.db.Close()
}

func (d *database) Size() int64 {
	info, err := os.Stat(d.path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (d *database) Write(records []Record, aggregates map[aggregateKey]aggregate) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		connections := tx.Bucket(bucketConnections)
		for _, record := range records {
			value, err := json.Marshal(record)
			if err != nil {
				return err
			}
			if err = connections.Put(connectionKey(record), value); err != nil {
				return err
			}
		}
		for key, update := range aggregates {
			bucketName := bucketMinutes
			if key.Hour {
				bucketName = bucketHours
			}
			bucket := tx.Bucket(bucketName)
			storageKey := dimensionKey(key)
			if current := bucket.Get(storageKey); current != nil {
				var existing aggregate
				if err := json.Unmarshal(current, &existing); err != nil {
					return err
				}
				update.Upload += existing.Upload
				update.Download += existing.Download
				update.Connections += existing.Connections
			}
			value, err := json.Marshal(update)
			if err != nil {
				return err
			}
			if err = bucket.Put(storageKey, value); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *database) Prune(cutoff time.Time) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		cutoffUnix := cutoff.Unix()
		for _, name := range [][]byte{bucketConnections, bucketMinutes, bucketHours} {
			bucket := tx.Bucket(name)
			cursor := bucket.Cursor()
			for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
				if len(key) < 8 || int64(binary.BigEndian.Uint64(key[:8])) >= cutoffUnix {
					break
				}
				if err := cursor.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (d *database) Connections(query Query) (ConnectionPage, error) {
	query = normalizeQuery(query)
	var page ConnectionPage
	err := d.db.View(func(tx *bbolt.Tx) error {
		cursor := tx.Bucket(bucketConnections).Cursor()
		for key, value := cursor.Last(); key != nil; key, value = cursor.Prev() {
			if len(key) < 8 {
				continue
			}
			closedAt := time.Unix(int64(binary.BigEndian.Uint64(key[:8])), 0)
			if closedAt.After(query.End) {
				continue
			}
			if closedAt.Before(query.Start) {
				break
			}
			var record Record
			if err := json.Unmarshal(value, &record); err != nil {
				return err
			}
			if !recordMatches(record, query.Search) {
				continue
			}
			if page.Total >= query.Offset && len(page.Data) < query.Limit {
				page.Data = append(page.Data, record)
			}
			page.Total++
		}
		return nil
	})
	return page, err
}

func (d *database) Summary(query Query) (Summary, error) {
	query = normalizeQuery(query)
	var summary Summary
	err := d.scanAggregates(query, func(item aggregate) {
		summary.Upload += item.Upload
		summary.Download += item.Download
		summary.Connections += item.Connections
	})
	return summary, err
}

func (d *database) Trend(query Query) ([]TrafficPoint, error) {
	query = normalizeQuery(query)
	points := make(map[int64]*TrafficPoint)
	err := d.scanAggregates(query, func(item aggregate) {
		point := points[item.Bucket]
		if point == nil {
			point = &TrafficPoint{Time: time.Unix(item.Bucket, 0).UTC()}
			points[item.Bucket] = point
		}
		point.Upload += item.Upload
		point.Download += item.Download
		point.Connections += item.Connections
	})
	if err != nil {
		return nil, err
	}
	result := make([]TrafficPoint, 0, len(points))
	for _, point := range points {
		result = append(result, *point)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Time.Before(result[j].Time) })
	return result, nil
}

func (d *database) Dimensions(name string, query Query) (DimensionPage, error) {
	query = normalizeQuery(query)
	values := make(map[string]*Dimension)
	err := d.scanAggregates(query, func(item aggregate) {
		value := aggregateDimension(item, name)
		if value == "" || query.Search != "" && !strings.Contains(strings.ToLower(value), strings.ToLower(query.Search)) {
			return
		}
		dimension := values[value]
		if dimension == nil {
			dimension = &Dimension{Value: value}
			values[value] = dimension
		}
		dimension.Upload += item.Upload
		dimension.Download += item.Download
		dimension.Connections += item.Connections
	})
	if err != nil {
		return DimensionPage{}, err
	}
	all := make([]Dimension, 0, len(values))
	for _, value := range values {
		all = append(all, *value)
	}
	sort.Slice(all, func(i, j int) bool {
		left := all[i].Upload + all[i].Download
		right := all[j].Upload + all[j].Download
		if left == right {
			return all[i].Value < all[j].Value
		}
		return left > right
	})
	page := DimensionPage{Total: len(all)}
	if query.Offset >= len(all) {
		return page, nil
	}
	end := min(query.Offset+query.Limit, len(all))
	page.Data = all[query.Offset:end]
	return page, nil
}

func (d *database) scanAggregates(query Query, callback func(item aggregate)) error {
	bucketName := bucketMinutes
	if query.End.Sub(query.Start) > 48*time.Hour {
		bucketName = bucketHours
	}
	return d.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).ForEach(func(_, value []byte) error {
			var item aggregate
			if err := json.Unmarshal(value, &item); err != nil {
				return err
			}
			itemTime := time.Unix(item.Bucket, 0)
			if itemTime.Before(query.Start) || itemTime.After(query.End) {
				return nil
			}
			callback(item)
			return nil
		})
	})
}

func normalizeQuery(query Query) Query {
	if query.End.IsZero() {
		query.End = time.Now()
	}
	if query.Start.IsZero() {
		query.Start = query.End.Add(-24 * time.Hour)
	}
	if query.Limit <= 0 {
		query.Limit = 100
	} else if query.Limit > 2000 {
		query.Limit = 2000
	}
	if query.Offset < 0 {
		query.Offset = 0
	}
	return query
}

func recordMatches(record Record, search string) bool {
	if search == "" {
		return true
	}
	search = strings.ToLower(search)
	return strings.Contains(strings.ToLower(record.Domain), search) ||
		strings.Contains(strings.ToLower(record.DestinationIP), search) ||
		strings.Contains(strings.ToLower(record.SourceIP), search) ||
		strings.Contains(strings.ToLower(record.Outbound), search) ||
		strings.Contains(strings.ToLower(record.Rule), search) ||
		strings.Contains(strings.ToLower(record.Process), search)
}

func aggregateDimension(item aggregate, name string) string {
	switch name {
	case "domains":
		return item.Domain
	case "ips":
		return item.IP
	case "outbounds":
		return item.Outbound
	case "rules":
		return item.Rule
	case "sources":
		return item.Source
	default:
		return ""
	}
}

func connectionKey(record Record) []byte {
	key := make([]byte, 8, 8+len(record.ID))
	binary.BigEndian.PutUint64(key, uint64(record.ClosedAt.Unix()))
	return append(key, record.ID...)
}

func dimensionKey(key aggregateKey) []byte {
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint64(prefix, uint64(key.Bucket))
	return bytes.Join([][]byte{
		prefix,
		[]byte(key.Domain),
		[]byte(key.IP),
		[]byte(key.Source),
		[]byte(key.Outbound),
		[]byte(key.Rule),
	}, []byte{0})
}

func mergeAggregate(target map[aggregateKey]aggregate, key aggregateKey, upload int64, download int64, connections int64) {
	item := target[key]
	item.Bucket = key.Bucket
	item.Domain = key.Domain
	item.IP = key.IP
	item.Source = key.Source
	item.Outbound = key.Outbound
	item.Rule = key.Rule
	item.Upload += upload
	item.Download += download
	item.Connections += connections
	target[key] = item
}
