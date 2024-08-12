package clashapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

type ruleProviderTestRuleSet struct {
	adapter.RuleSet
}

func (r *ruleProviderTestRuleSet) Name() string {
	return "remote"
}

func (r *ruleProviderTestRuleSet) Type() string {
	return constant.RuleSetTypeRemote
}

func (r *ruleProviderTestRuleSet) Format() string {
	return constant.RuleSetFormatSource
}

func (r *ruleProviderTestRuleSet) RuleCount() uint64 {
	return 1
}

func (r *ruleProviderTestRuleSet) UpdatedTime() time.Time {
	return time.Unix(0, 0).UTC()
}

func TestGetRuleProviderContentType(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/providers/rules/remote", nil)
	request = request.WithContext(context.WithValue(request.Context(), CtxKeyProvider, &ruleProviderTestRuleSet{}))
	response := httptest.NewRecorder()

	getRuleProvider(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "application/json", response.Header().Get("Content-Type"))
	require.JSONEq(t, `{
		"name": "remote",
		"type": "Rule",
		"vehicleType": "REMOTE",
		"behavior": "SOURCE",
		"ruleCount": 1,
		"updatedAt": "1970-01-01T00:00:00+00:00"
	}`, response.Body.String())
}
