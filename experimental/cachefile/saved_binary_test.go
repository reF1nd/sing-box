package cachefile

import (
	"bytes"
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/hash"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/varbin"

	"github.com/stretchr/testify/require"
)

func legacySavedBinary(t *testing.T, version byte, value *adapter.SavedBinary) []byte {
	t.Helper()
	var buffer bytes.Buffer
	buffer.WriteByte(version)
	_, err := varbin.WriteUvarint(&buffer, uint64(len(value.Content)))
	require.NoError(t, err)
	buffer.Write(value.Content)
	require.NoError(t, binary.Write(&buffer, binary.BigEndian, value.LastUpdated.Unix()))
	_, err = varbin.WriteUvarint(&buffer, uint64(len(value.LastEtag)))
	require.NoError(t, err)
	buffer.WriteString(value.LastEtag)
	if version == 2 {
		_, err = varbin.WriteUvarint(&buffer, uint64(len(value.URLHash)))
		require.NoError(t, err)
		buffer.Write(value.URLHash)
	}
	return buffer.Bytes()
}

func TestBranchBinaryNamespaces(t *testing.T) {
	value := &adapter.SavedBinary{Content: []byte("payload"), LastUpdated: time.Unix(1750000000, 0), LastEtag: "etag", URLHash: []byte("url"), Hash: hash.MakeHash([]byte("file content"))}
	official, err := value.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, legacySavedBinary(t, 2, value), official, "Hash must not change official encoding")
	data, err := marshalBranchBinary(value)
	require.NoError(t, err)
	require.Equal(t, byte(1), data[len(branchBinaryMagic)])
	decoded, err := unmarshalBranchBinary(data)
	require.NoError(t, err)
	require.Equal(t, value, decoded)
	for _, version := range []byte{1, 2} {
		var envelope bytes.Buffer
		envelope.WriteString(branchBinaryMagic)
		envelope.WriteByte(1)
		payload := legacySavedBinary(t, version, value)
		_, err = varbin.WriteUvarint(&envelope, uint64(len(payload)))
		require.NoError(t, err)
		envelope.Write(payload)
		envelope.Write(value.Hash.Bytes())
		decoded, err = unmarshalBranchBinary(envelope.Bytes())
		require.NoError(t, err)
		require.Equal(t, value.Hash, decoded.Hash)
		require.Equal(t, value.Content, decoded.Content)
	}
	badVersion := bytes.Clone(data)
	badVersion[len(branchBinaryMagic)]++
	badMagic := bytes.Clone(data)
	badMagic[0]++
	badPayloadVersion := bytes.Clone(data)
	// This fixture's official payload length uses a single-byte varint.
	badPayloadVersion[len(branchBinaryMagic)+2] = 3
	for _, bad := range [][]byte{nil, official, badVersion, badMagic, badPayloadVersion, data[:len(data)-1], append(bytes.Clone(data), 0), append([]byte(branchBinaryMagic+"\x01"), bytes.Repeat([]byte{0xff}, 10)...)} {
		_, err = unmarshalBranchBinary(bad)
		require.Error(t, err)
	}
}

func TestBranchCacheMigrationAndIsolation(t *testing.T) {
	for _, cacheID := range []string{"", "profile"} {
		t.Run(cacheID, func(t *testing.T) {
			options := option.CacheFileOptions{Path: filepath.Join(t.TempDir(), "cache.db"), CacheID: cacheID}
			cache := New(context.Background(), logger.NOP(), options)
			require.NoError(t, cache.Start(adapter.StartStateInitialize))
			old := &adapter.SavedBinary{Content: []byte("old rules"), LastUpdated: time.Unix(1750000000, 0), LastEtag: "old", URLHash: []byte("old url")}
			for _, version := range []byte{1, 2} {
				tag := string(rune('0' + version))
				legacy := legacySavedBinary(t, version, old)
				require.NoError(t, cache.DB.Update(func(tx *bbolt.Tx) error {
					bucket, err := cache.createBucket(tx, bucketRuleSet)
					if err != nil {
						return err
					}
					return bucket.Put([]byte(tag), legacy)
				}))
				restored := cache.LoadRuleSet(tag)
				require.NotNil(t, restored)
				require.Equal(t, old.Content, restored.Content)
				require.Equal(t, hash.MakeHash(old.Content), restored.Hash)
				updated := &adapter.SavedBinary{Content: []byte("new rules"), Hash: hash.MakeHash([]byte("new file")), LastUpdated: old.LastUpdated, LastEtag: "new", URLHash: []byte("new url")}
				require.NoError(t, cache.SaveRuleSet(tag, updated))
				require.NoError(t, cache.SaveSubscription(tag, old))
				require.Equal(t, updated, cache.LoadRuleSet(tag))
				require.Equal(t, old, cache.LoadSubscription(tag))
				require.NoError(t, cache.DB.View(func(tx *bbolt.Tx) error {
					require.Equal(t, legacy, cache.bucket(tx, bucketRuleSet).Get([]byte(tag)), "do not overwrite official bucket")
					return nil
				}))
			}
			require.NoError(t, cache.SaveExternalUI("ui", old))
			require.NoError(t, cache.DB.View(func(tx *bbolt.Tx) error {
				require.Equal(t, legacySavedBinary(t, 2, old), cache.bucket(tx, bucketExternalUI).Get([]byte("ui")))
				return nil
			}))
			require.NoError(t, cache.Close())
			cache = New(context.Background(), logger.NOP(), options)
			require.NoError(t, cache.Start(adapter.StartStateInitialize))
			defer cache.Close()
			require.Equal(t, []byte("new rules"), cache.LoadRuleSet("1").Content)
			require.Equal(t, old, cache.LoadSubscription("1"))
			require.NoError(t, cache.DB.Update(func(tx *bbolt.Tx) error {
				return cache.bucket(tx, bucketBranch).Bucket(bucketRuleSet).Put([]byte("1"), []byte("corrupt"))
			}))
			require.Nil(t, cache.LoadRuleSet("1"), "do not fall back to stale official data")
			other := &CacheFile{DB: cache.DB, cacheID: []byte("\x00other"), logger: logger.NOP()}
			require.Nil(t, other.LoadSubscription("1"))
		})
	}
}
