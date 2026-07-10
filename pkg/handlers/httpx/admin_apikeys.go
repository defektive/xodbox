package httpx

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/defektive/xodbox/pkg/model"
)

// apiKeyView is the safe (no secret) representation of an API key.
type apiKeyView struct {
	ID         uint       `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
}

func toAPIKeyView(k model.APIKey) apiKeyView {
	return apiKeyView{
		ID:         k.ID,
		Name:       k.Name,
		Prefix:     k.Prefix,
		CreatedAt:  k.CreatedAt,
		LastUsedAt: k.LastUsedAt,
		ExpiresAt:  k.ExpiresAt,
	}
}

func (a *adminAuth) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	me := userFromContext(r.Context())
	keys := model.ListAPIKeys(me.ID)
	out := make([]apiKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, toAPIKeyView(k))
	}
	writeJSON(w, http.StatusOK, out)
}

type createAPIKeyRequest struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (a *adminAuth) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	me := userFromContext(r.Context())
	var req createAPIKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	full, rec, err := model.NewAPIKey(me.ID, req.Name, req.ExpiresAt)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create key")
		return
	}
	// The plaintext key is returned exactly once here.
	writeJSON(w, http.StatusCreated, struct {
		apiKeyView
		Key string `json:"key"`
	}{toAPIKeyView(*rec), full})
}

func (a *adminAuth) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	me := userFromContext(r.Context())
	if err := model.DeleteAPIKey(id, me.ID, me.IsAdmin()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
