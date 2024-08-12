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

func TestRemoteRuleSetMultipleTagsPath(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name         string
		path         string
		requireError bool
	}{
		{
			name: "empty",
		},
		{
			name: "placeholder",
			path: "{tag}.json",
		},
		{
			name:         "shared",
			path:         "shared.json",
			requireError: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			content := `{
				"type": "remote",
				"tag": ["a", "b"],
				"format": "source",
				"path": "` + testCase.path + `",
				"url": "https://example.com/{tag}.json"
			}`
			var ruleSet RuleSet
			err := json.Unmarshal([]byte(content), &ruleSet)
			if testCase.requireError {
				require.ErrorContains(t, err, "missing {tag} placeholder in path")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
