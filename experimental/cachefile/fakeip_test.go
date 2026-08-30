package cachefile

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func newTestCacheFile(t *testing.T) *CacheFile {
	t.Helper()
	cacheFile := New(context.Background(), logger.NOP(), option.CacheFileOptions{
		Path: filepath.Join(t.TempDir(), "cache.db"),
	})
	if err := cacheFile.Start(adapter.StartStateInitialize); err != nil {
		t.Fatalf("start cache file: %v", err)
	}
	t.Cleanup(func() {
		_ = cacheFile.Close()
	})
	return cacheFile
}

// TestFakeIPResetWithoutIPv6Bucket covers a database that only ever held IPv4
// records, so the domain6 bucket was never created. Deleting a missing bucket
// reports ErrBucketNotFound, and a batch that returns an error rolls back, which
// used to leave every mapping in place and let a changed FakeIP range keep
// handing out addresses allocated from the previous one.
func TestFakeIPResetWithoutIPv6Bucket(t *testing.T) {
	t.Parallel()
	cacheFile := newTestCacheFile(t)
	address := netip.MustParseAddr("11.0.0.20")
	if err := cacheFile.FakeIPStore(address, "www.google.com"); err != nil {
		t.Fatalf("store FakeIP record: %v", err)
	}
	if err := cacheFile.FakeIPReset(); err != nil {
		t.Fatalf("reset FakeIP cache: %v", err)
	}
	if storedAddress, loaded := cacheFile.FakeIPLoadDomain("www.google.com", false); loaded {
		t.Fatalf("domain record survived reset: %s", storedAddress)
	}
	if domain, loaded := cacheFile.FakeIPLoad(address); loaded {
		t.Fatalf("address record survived reset: %s", domain)
	}
}

func TestFakeIPResetWithoutRecords(t *testing.T) {
	t.Parallel()
	cacheFile := newTestCacheFile(t)
	if err := cacheFile.FakeIPReset(); err != nil {
		t.Fatalf("reset empty FakeIP cache: %v", err)
	}
}

func TestFakeIPResetBothFamilies(t *testing.T) {
	t.Parallel()
	cacheFile := newTestCacheFile(t)
	inet4Address := netip.MustParseAddr("11.0.0.20")
	inet6Address := netip.MustParseAddr("fc00::20")
	if err := cacheFile.FakeIPStore(inet4Address, "www.google.com"); err != nil {
		t.Fatalf("store IPv4 FakeIP record: %v", err)
	}
	if err := cacheFile.FakeIPStore(inet6Address, "www.google.com"); err != nil {
		t.Fatalf("store IPv6 FakeIP record: %v", err)
	}
	if err := cacheFile.FakeIPReset(); err != nil {
		t.Fatalf("reset FakeIP cache: %v", err)
	}
	for _, isIPv6 := range []bool{false, true} {
		if storedAddress, loaded := cacheFile.FakeIPLoadDomain("www.google.com", isIPv6); loaded {
			t.Fatalf("domain record survived reset (ipv6=%v): %s", isIPv6, storedAddress)
		}
	}
}
