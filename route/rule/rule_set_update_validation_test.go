package rule

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"github.com/stretchr/testify/require"
)

type fakeDNSRuleSetUpdateValidator struct {
	validate func(tag string, metadata adapter.RuleSetMetadata) error
}

func (v *fakeDNSRuleSetUpdateValidator) ValidateRuleSetMetadataUpdate(tag string, metadata adapter.RuleSetMetadata) error {
	if v.validate == nil {
		return nil
	}
	return v.validate(tag, metadata)
}

func TestLocalRuleSetReloadRulesRejectsInvalidUpdateBeforeCommit(t *testing.T) {
	t.Parallel()

	var callbackCount atomic.Int32
	ctx := service.ContextWith[adapter.DNSRuleSetUpdateValidator](context.Background(), &fakeDNSRuleSetUpdateValidator{
		validate: func(tag string, metadata adapter.RuleSetMetadata) error {
			require.Equal(t, "dynamic-set", tag)
			if metadata.ContainsDNSQueryTypeRule {
				return E.New("dns conflict")
			}
			return nil
		},
	})
	ruleSet := &LocalRuleSet{
		abstractRuleSet: abstractRuleSet{
			ctx:    ctx,
			tag:    "dynamic-set",
			format: C.RuleSetFormatSource,
			logger: logger.NOP(),
		},
	}
	_ = ruleSet.callbacks.PushBack(func(adapter.RuleSet) {
		callbackCount.Add(1)
	})

	err := ruleSet.reloadRules([]option.HeadlessRule{{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			Domain: badoption.Listable[string]{"example.com"},
		},
	}}, ruleSet)
	require.NoError(t, err)
	require.Equal(t, int32(1), callbackCount.Load())
	require.False(t, ruleSet.Metadata().ContainsDNSQueryTypeRule)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))

	err = ruleSet.reloadRules([]option.HeadlessRule{{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			QueryType: badoption.Listable[option.DNSQueryType]{option.DNSQueryType(1)},
		},
	}}, ruleSet)
	require.ErrorContains(t, err, "dns conflict")
	require.Equal(t, int32(1), callbackCount.Load())
	require.False(t, ruleSet.Metadata().ContainsDNSQueryTypeRule)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))
}

func TestRemoteRuleSetLoadBytesRejectsInvalidUpdateBeforeCommit(t *testing.T) {
	t.Parallel()

	var callbackCount atomic.Int32
	ctx := service.ContextWith[adapter.DNSRuleSetUpdateValidator](context.Background(), &fakeDNSRuleSetUpdateValidator{
		validate: func(tag string, metadata adapter.RuleSetMetadata) error {
			require.Equal(t, "dynamic-set", tag)
			if metadata.ContainsDNSQueryTypeRule {
				return E.New("dns conflict")
			}
			return nil
		},
	})
	ctx = filemanager.WithDefault(ctx, "", t.TempDir(), os.Getuid(), os.Getgid())
	ruleSet := &RemoteRuleSet{
		abstractRuleSet: abstractRuleSet{
			ctx:    ctx,
			tag:    "dynamic-set",
			format: C.RuleSetFormatSource,
		},
		options: option.RemoteRuleSet{},
	}
	_ = ruleSet.callbacks.PushBack(func(adapter.RuleSet) {
		callbackCount.Add(1)
	})

	err := ruleSet.loadBytes([]byte(`{"version":4,"rules":[{"domain":["example.com"]}]}`), ruleSet)
	require.NoError(t, err)
	require.Equal(t, int32(1), callbackCount.Load())
	require.False(t, ruleSet.Metadata().ContainsDNSQueryTypeRule)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))

	err = ruleSet.loadBytes([]byte(`{"version":4,"rules":[{"query_type":["A"]}]}`), ruleSet)
	require.ErrorContains(t, err, "dns conflict")
	require.Equal(t, int32(1), callbackCount.Load())
	require.False(t, ruleSet.Metadata().ContainsDNSQueryTypeRule)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))
}

func TestRemoteRuleSetSaveCacheFailureDoesNotAdvanceEtag(t *testing.T) {
	t.Parallel()
	const body = `{"version":4,"rules":[{"domain":["example.com"]}]}`
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("If-None-Match") == `"v2"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Etag", `"v2"`)
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	dir := t.TempDir()
	// Point path to a directory so WriteFile fails.
	unwritablePath := filepath.Join(dir, "blocker")
	require.NoError(t, os.MkdirAll(unwritablePath, 0o755))

	ctx := filemanager.WithDefault(context.Background(), "", dir, os.Getuid(), os.Getgid())
	ruleSet := &RemoteRuleSet{
		abstractRuleSet: abstractRuleSet{
			ctx:    ctx,
			tag:    "remote-set",
			format: C.RuleSetFormatSource,
			path:   unwritablePath,
			logger: logger.NOP(),
		},
		url:        server.URL,
		options:    option.RemoteRuleSet{URL: server.URL},
		httpClient: server.Client(),
		lastEtag:   `"v1"`,
	}

	err := ruleSet.fetch(ctx, false)
	require.Error(t, err)
	require.Equal(t, `"v1"`, ruleSet.lastEtag, "failed disk write must not advance ETag")
	require.False(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}), "failed disk write must not publish new rules")

	// Remove the blocker directory so retry succeeds and writes the file.
	require.NoError(t, os.Remove(unwritablePath))
	require.NoError(t, ruleSet.fetch(ctx, false))
	require.Equal(t, `"v2"`, ruleSet.lastEtag)
	require.True(t, ruleSet.Match(&adapter.InboundContext{Domain: "example.com"}))
	require.Equal(t, int32(2), requests.Load())
	written, err := os.ReadFile(unwritablePath)
	require.NoError(t, err)
	require.Equal(t, body, string(written))

	// Existing regular file permissions (e.g. 0640 on Unix) must be preserved across atomic updates.
	require.NoError(t, os.Chmod(unwritablePath, 0o640))
	preInfo, err := os.Stat(unwritablePath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o640), preInfo.Mode().Perm())
	}
	require.NoError(t, ruleSet.saveCacheFile([]byte(body)))
	info, err := os.Stat(unwritablePath)
	require.NoError(t, err)
	require.Equal(t, preInfo.Mode().Perm(), info.Mode().Perm())
}
