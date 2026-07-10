package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/defektive/xodbox/pkg/model"
	"gorm.io/gorm"
)

// sinkView is the API representation of a sink, with a live event count.
type sinkView struct {
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	EventCount  int64     `json:"event_count"`
}

func toSinkView(s model.Sink) sinkView {
	return sinkView{
		Slug:        s.Slug,
		Description: s.Description,
		CreatedAt:   s.CreatedAt,
		EventCount:  model.SinkEventCount(s.Slug),
	}
}

func (a *adminAuth) handleSinks(w http.ResponseWriter, r *http.Request) {
	sinks := model.ListSinks()
	out := make([]sinkView, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, toSinkView(s))
	}
	writeJSON(w, http.StatusOK, out)
}

type createSinkRequest struct {
	Slug        string `json:"slug"`
	Description string `json:"description"`
}

func (a *adminAuth) handleCreateSink(w http.ResponseWriter, r *http.Request) {
	var req createSinkRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s, err := model.CreateSink(strings.TrimSpace(req.Slug), req.Description)
	if err != nil {
		switch {
		case errors.Is(err, model.ErrInvalidSlug), errors.Is(err, model.ErrSlugExists):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, "could not create sink")
		}
		return
	}
	writeJSON(w, http.StatusCreated, toSinkView(*s))
}

// sinkDetail is a sink plus a page of its attributed events, newest first.
type sinkDetail struct {
	sinkView
	Events []interactionSummary `json:"events"`
	Total  int64                `json:"total"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
}

func (a *adminAuth) handleSink(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	s, err := model.SinkBySlug(slug)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeErr(w, http.StatusNotFound, "sink not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	limit := atoiDefault(r.URL.Query().Get("limit"), 50)
	if limit > maxInteractionPage {
		limit = maxInteractionPage
	}
	if limit < 1 {
		limit = 1
	}
	offset := atoiDefault(r.URL.Query().Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}

	rows := model.SinkEvents(s.Slug, limit, offset)
	events := make([]interactionSummary, 0, len(rows))
	for _, row := range rows {
		events = append(events, summarize(row))
	}
	writeJSON(w, http.StatusOK, sinkDetail{
		sinkView: toSinkView(*s),
		Events:   events,
		Total:    model.SinkEventCount(s.Slug),
		Limit:    limit,
		Offset:   offset,
	})
}

func (a *adminAuth) handleDeleteSink(w http.ResponseWriter, r *http.Request) {
	if err := model.DeleteSink(r.PathValue("slug")); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not delete sink")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
