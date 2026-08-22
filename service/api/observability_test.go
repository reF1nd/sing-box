package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestObservabilityAuthenticationAndRouting(t *testing.T) {
	target := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/status", request.URL.Path)
		writer.WriteHeader(http.StatusNoContent)
	})
	handler := &webBridge{
		observability: authenticateObservability("secret", http.StripPrefix("/observability/v1", target)),
	}

	request := httptest.NewRequest(http.MethodGet, "/observability/v1/status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	var errorResponse struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &errorResponse))
	require.Equal(t, "unauthorized", errorResponse.Error.Code)

	request = httptest.NewRequest(http.MethodGet, "/observability/v1/status", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusNoContent, response.Code)
}
