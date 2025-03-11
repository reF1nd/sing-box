package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestProviderRemotePathConflict(t *testing.T) {
	var options ProviderRemoteOptions
	err := json.Unmarshal([]byte(`{
		"url": "https://example.com/provider.json",
		"path": "provider.json",
		"initial_path": "initial-provider.json"
	}`), &options)
	require.ErrorContains(t, err, "path and initial_path are mutually exclusive")
}

func TestProviderRemoteSinglePath(t *testing.T) {
	for _, content := range []string{
		`{"url":"https://example.com/provider.json","path":"provider.json"}`,
		`{"url":"https://example.com/provider.json","initial_path":"initial-provider.json"}`,
	} {
		var options ProviderRemoteOptions
		require.NoError(t, json.Unmarshal([]byte(content), &options))
	}
}
