package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestRemoteRuleSetPathConflict(t *testing.T) {
	var ruleSet RuleSet
	err := json.Unmarshal([]byte(`{
		"type": "remote",
		"tag": "remote",
		"format": "source",
		"path": "remote.json",
		"initial_path": "initial.json",
		"url": "https://example.com/remote.json"
	}`), &ruleSet)
	require.ErrorContains(t, err, "path and initial_path are mutually exclusive")
}
