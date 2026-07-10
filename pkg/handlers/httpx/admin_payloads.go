package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"gorm.io/gorm"
)

const maxPayloadBody = 512 << 10 // 512 KiB

// payloadView is the admin API representation of an HTTPX payload. It maps the
// httpx.Payload (whose struct tags are legacy) to clean snake_case JSON and
// flattens the HTTP response Data (headers/body/status).
type payloadView struct {
	ID               uint              `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Type             string            `json:"type"`
	Pattern          string            `json:"pattern"`
	IsFinal          bool              `json:"is_final"`
	SortOrder        int               `json:"sort_order"`
	InternalFunction string            `json:"internal_function"`
	Headers          map[string]string `json:"headers"`
	Body             string            `json:"body"`
	StatusCode       string            `json:"status_code"`
}

func toPayloadView(p *Payload) payloadView {
	return payloadView{
		ID:               p.ID,
		Name:             p.Name,
		Description:      p.Description,
		Type:             p.Type,
		Pattern:          p.Pattern,
		IsFinal:          p.IsFinal,
		SortOrder:        p.SortOrder,
		InternalFunction: p.InternalFunction,
		Headers:          p.Data.Headers,
		Body:             p.Data.Body,
		StatusCode:       p.Data.StatusCode,
	}
}

func (v payloadView) toPayload() *Payload {
	p := NewHTTPPayload()
	p.Name = v.Name
	p.Description = v.Description
	p.Pattern = v.Pattern
	p.IsFinal = v.IsFinal
	p.SortOrder = v.SortOrder
	p.InternalFunction = v.InternalFunction
	p.Data = PayloadData{Headers: v.Headers, Body: v.Body, StatusCode: v.StatusCode}
	return p
}

func (a *adminAuth) handlePayloads(w http.ResponseWriter, r *http.Request) {
	rows := ListPayloads()
	items := make([]payloadView, 0, len(rows))
	for _, p := range rows {
		items = append(items, toPayloadView(p))
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *adminAuth) handlePayload(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := PayloadByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, toPayloadView(p))
}

func (a *adminAuth) handleCreatePayload(w http.ResponseWriter, r *http.Request) {
	v, ok := decodePayload(w, r)
	if !ok {
		return
	}
	p := v.toPayload()
	if err := CreatePayload(p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toPayloadView(p))
}

func (a *adminAuth) handleUpdatePayload(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	v, ok := decodePayload(w, r)
	if !ok {
		return
	}
	p, err := UpdatePayload(id, v.toPayload())
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toPayloadView(p))
}

func (a *adminAuth) handleDeletePayload(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := DeletePayload(id); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodePayload(w http.ResponseWriter, r *http.Request) (payloadView, bool) {
	var v payloadView
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPayloadBody)).Decode(&v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return v, false
	}
	return v, true
}

func pathID(w http.ResponseWriter, r *http.Request) (uint, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return uint(id), true
}
