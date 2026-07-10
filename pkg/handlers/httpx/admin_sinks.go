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
	return sinkViewCounted(s, model.SinkEventCount(s.Slug))
}

// sinkViewCounted builds the view with a caller-supplied count, so a handler
// that already knows the event count doesn't run the COUNT query twice.
func sinkViewCounted(s model.Sink, count int64) sinkView {
	return sinkView{
		Slug:        s.Slug,
		Description: s.Description,
		CreatedAt:   s.CreatedAt,
		EventCount:  count,
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

// sinkDetail is a sink plus a page of its attributed events (full detail so the
// UI can render an event timeline), newest first.
type sinkDetail struct {
	sinkView
	Events []interactionDetail `json:"events"`
	Total  int64               `json:"total"`
	Limit  int                 `json:"limit"`
	Offset int                 `json:"offset"`
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
	events := make([]interactionDetail, 0, len(rows))
	for i := range rows {
		events = append(events, toDetail(&rows[i]))
	}
	total := model.SinkEventCount(s.Slug)
	writeJSON(w, http.StatusOK, sinkDetail{
		sinkView: sinkViewCounted(*s, total),
		Events:   events,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	})
}

type updateSinkRequest struct {
	Description string `json:"description"`
}

func (a *adminAuth) handleUpdateSink(w http.ResponseWriter, r *http.Request) {
	var req updateSinkRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s, err := model.UpdateSinkDescription(r.PathValue("slug"), req.Description)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeErr(w, http.StatusNotFound, "sink not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not update sink")
		return
	}
	writeJSON(w, http.StatusOK, toSinkView(*s))
}

func (a *adminAuth) handleDeleteSink(w http.ResponseWriter, r *http.Request) {
	if err := model.DeleteSink(r.PathValue("slug")); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not delete sink")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
