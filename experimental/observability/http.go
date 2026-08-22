package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type httpHandler struct {
	manager *Manager
}

func (h *httpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	endpoint := endpointName(request.URL.Path)
	trackedWriter := &trackingResponseWriter{ResponseWriter: writer, status: http.StatusOK}
	startedAt := time.Now()
	defer func() {
		h.manager.apiMetrics.observe(endpoint, trackedWriter.status, trackedWriter.bytes, time.Since(startedAt))
	}()
	writer = trackedWriter
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", "", "")
		return
	}
	path := strings.TrimPrefix(request.URL.Path, "/observability/v1")
	switch strings.TrimSuffix(path, "/") {
	case "":
		writeJSON(writer, http.StatusOK, map[string]any{
			"name":      "sing-box observability API",
			"version":   1,
			"endpoints": h.manager.capabilities().Endpoints,
		})
	case "/capabilities":
		writeJSON(writer, http.StatusOK, h.manager.capabilities())
	case "/metrics":
		h.metrics(writer)
	case "/status":
		writeJSON(writer, http.StatusOK, h.manager.status())
	case "/connections/active":
		h.activeConnections(writer, request)
	case "/connections/recent":
		h.recentConnections(writer, request)
	case "/top":
		h.top(writer, request)
	case "/events":
		h.events(writer, request)
	default:
		writeError(writer, http.StatusNotFound, "not_found", "not found", "", "")
	}
}

func (h *httpHandler) metrics(writer http.ResponseWriter) {
	var content bytes.Buffer
	if err := h.manager.writePrometheus(&content); err != nil {
		writeError(writer, http.StatusInternalServerError, "metrics_generation_failed", err.Error(), "", "")
		return
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(content.Bytes())
}

func (h *httpHandler) activeConnections(writer http.ResponseWriter, request *http.Request) {
	if !validateQueryParameters(writer, request, "cursor", "limit") {
		return
	}
	limit, err := queryInteger(request, "limit", 100)
	if err != nil || limit < 1 || limit > MaxActivePageSize {
		writeError(writer, http.StatusBadRequest, "invalid_query_parameter", fmt.Sprintf("limit must be between 1 and %d", MaxActivePageSize), "limit", strconv.Itoa(MaxActivePageSize))
		return
	}
	result, err := h.manager.activeConnections(request.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query_parameter", err.Error(), "cursor", "")
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (h *httpHandler) recentConnections(writer http.ResponseWriter, request *http.Request) {
	if !validateQueryParameters(writer, request, "cursor", "limit", "window") {
		return
	}
	limit, err := queryInteger(request, "limit", 100)
	if err != nil || limit < 1 || limit > h.manager.recentConnections {
		writeError(writer, http.StatusBadRequest, "invalid_query_parameter", fmt.Sprintf("limit must be between 1 and %d", h.manager.recentConnections), "limit", strconv.Itoa(h.manager.recentConnections))
		return
	}
	window, err := queryDuration(request, "window", h.manager.recentTTL)
	if err != nil || window <= 0 || window > h.manager.recentTTL {
		writeError(writer, http.StatusBadRequest, "invalid_query_parameter", "window must be positive and no greater than recent_ttl", "window", h.manager.recentTTL.String())
		return
	}
	result, err := h.manager.recentConnectionPage(request.URL.Query().Get("cursor"), limit, window)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query_parameter", err.Error(), "cursor", "")
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (h *httpHandler) top(writer http.ResponseWriter, request *http.Request) {
	if !validateQueryParameters(writer, request, "dimension", "limit", "window") {
		return
	}
	dimension := request.URL.Query().Get("dimension")
	if dimension == "" {
		dimension = "outbound"
	}
	limit, err := queryInteger(request, "limit", h.manager.topKSize)
	if err != nil || limit < 1 || limit > h.manager.topKSize {
		writeError(writer, http.StatusBadRequest, "invalid_query_parameter", fmt.Sprintf("limit must be between 1 and %d", h.manager.topKSize), "limit", strconv.Itoa(h.manager.topKSize))
		return
	}
	window, err := queryDuration(request, "window", h.manager.recentTTL)
	if err != nil || window <= 0 || window > h.manager.recentTTL {
		writeError(writer, http.StatusBadRequest, "invalid_query_parameter", "window must be positive and no greater than recent_ttl", "window", h.manager.recentTTL.String())
		return
	}
	result, err := h.manager.topDimensions(dimension, window, limit)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query_parameter", err.Error(), "dimension", "")
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (h *httpHandler) events(writer http.ResponseWriter, request *http.Request) {
	if !validateQueryParameters(writer, request, "heartbeat") {
		return
	}
	flusher, loaded := writer.(http.Flusher)
	if !loaded {
		writeError(writer, http.StatusInternalServerError, "streaming_not_supported", "streaming is not supported", "", "")
		return
	}
	heartbeat, err := queryDuration(request, "heartbeat", 15*time.Second)
	if err != nil || heartbeat < time.Second || heartbeat > time.Minute {
		writeError(writer, http.StatusBadRequest, "invalid_query_parameter", "heartbeat must be between 1s and 1m", "heartbeat", "1m")
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(writer, "retry: 3000\n\n")
	flusher.Flush()
	h.manager.apiMetrics.sseSubscribers.Add(1)
	defer h.manager.apiMetrics.sseSubscribers.Add(-1)
	err = h.manager.streamEvents(request.Context(), heartbeat, func(event *Event) error {
		if event == nil {
			_, writeErr := fmt.Fprint(writer, ": keepalive\n\n")
			flusher.Flush()
			return writeErr
		}
		content, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return marshalErr
		}
		if _, writeErr := fmt.Fprintf(writer, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, event.Type, content); writeErr != nil {
			return writeErr
		}
		h.manager.apiMetrics.sseEvents.Add(1)
		flusher.Flush()
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return
	}
}

func queryInteger(request *http.Request, name string, fallback int) (int, error) {
	value := request.URL.Query().Get(name)
	if value == "" {
		return fallback, nil
	}
	return strconv.Atoi(value)
}

func queryDuration(request *http.Request, name string, fallback time.Duration) (time.Duration, error) {
	value := request.URL.Query().Get(name)
	if value == "" {
		return fallback, nil
	}
	return time.ParseDuration(value)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, code string, message string, parameter string, maximum string) {
	writeJSON(writer, status, APIError{
		Error: APIErrorDetail{Code: code, Message: message, Parameter: parameter, Maximum: maximum},
	})
}

func validateQueryParameters(writer http.ResponseWriter, request *http.Request, allowed ...string) bool {
	allowedParameters := make(map[string]struct{}, len(allowed))
	for _, parameter := range allowed {
		allowedParameters[parameter] = struct{}{}
	}
	for parameter := range request.URL.Query() {
		if _, loaded := allowedParameters[parameter]; !loaded {
			writeError(writer, http.StatusBadRequest, "unknown_query_parameter", "unsupported query parameter: "+parameter, parameter, "")
			return false
		}
	}
	return true
}

type trackingResponseWriter struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (w *trackingResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *trackingResponseWriter) Write(content []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(content)
	w.bytes += written
	return written, err
}

func (w *trackingResponseWriter) Flush() {
	if flusher, loaded := w.ResponseWriter.(http.Flusher); loaded {
		flusher.Flush()
	}
}

func endpointName(path string) string {
	path = strings.TrimSuffix(strings.TrimPrefix(path, "/observability/v1"), "/")
	if path == "" {
		return "root"
	}
	switch path {
	case "/capabilities", "/metrics", "/status", "/connections/active", "/connections/recent", "/top", "/events":
		return strings.TrimPrefix(path, "/")
	default:
		return "unknown"
	}
}
