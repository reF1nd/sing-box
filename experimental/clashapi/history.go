package clashapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/experimental/connectionhistory"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func connectionHistoryRouter(history connectionhistory.Service) http.Handler {
	router := chi.NewRouter()
	router.Get("/summary", func(w http.ResponseWriter, r *http.Request) {
		query, loaded := parseHistoryQuery(w, r)
		if !loaded {
			return
		}
		result, err := history.Summary(query)
		renderHistoryResult(w, r, result, err)
	})
	router.Get("/trend", func(w http.ResponseWriter, r *http.Request) {
		query, loaded := parseHistoryQuery(w, r)
		if !loaded {
			return
		}
		result, err := history.Trend(query)
		renderHistoryResult(w, r, result, err)
	})
	router.Get("/connections", func(w http.ResponseWriter, r *http.Request) {
		query, loaded := parseHistoryQuery(w, r)
		if !loaded {
			return
		}
		result, err := history.Connections(query)
		renderHistoryResult(w, r, result, err)
	})
	for _, dimension := range []string{"domains", "ips", "outbounds", "rules", "sources"} {
		router.Get("/"+dimension, func(w http.ResponseWriter, r *http.Request) {
			query, loaded := parseHistoryQuery(w, r)
			if !loaded {
				return
			}
			result, err := history.Dimensions(dimension, query)
			renderHistoryResult(w, r, result, err)
		})
	}
	router.Get("/status", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, history.Status())
	})
	return router
}

func parseHistoryQuery(w http.ResponseWriter, r *http.Request) (connectionhistory.Query, bool) {
	values := r.URL.Query()
	query := connectionhistory.Query{Search: values.Get("search")}
	var err error
	if start := values.Get("start"); start != "" {
		query.Start, err = time.Parse(time.RFC3339, start)
		if err != nil {
			renderHistoryBadRequest(w, r, "invalid start time")
			return connectionhistory.Query{}, false
		}
	}
	if end := values.Get("end"); end != "" {
		query.End, err = time.Parse(time.RFC3339, end)
		if err != nil {
			renderHistoryBadRequest(w, r, "invalid end time")
			return connectionhistory.Query{}, false
		}
	}
	if !query.Start.IsZero() && !query.End.IsZero() && query.Start.After(query.End) {
		renderHistoryBadRequest(w, r, "start must not be after end")
		return connectionhistory.Query{}, false
	}
	if limit := values.Get("limit"); limit != "" {
		query.Limit, err = strconv.Atoi(limit)
		if err != nil || query.Limit < 1 || query.Limit > 2000 {
			renderHistoryBadRequest(w, r, "limit must be between 1 and 2000")
			return connectionhistory.Query{}, false
		}
	}
	if offset := values.Get("offset"); offset != "" {
		query.Offset, err = strconv.Atoi(offset)
		if err != nil || query.Offset < 0 {
			renderHistoryBadRequest(w, r, "offset must be zero or greater")
			return connectionhistory.Query{}, false
		}
	}
	return query, true
}

func renderHistoryResult(w http.ResponseWriter, r *http.Request, result any, err error) {
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.JSON(w, r, result)
}

func renderHistoryBadRequest(w http.ResponseWriter, r *http.Request, message string) {
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, newError(message))
}
