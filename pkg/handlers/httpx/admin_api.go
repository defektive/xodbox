package httpx

import (
	"net/http"
	"strconv"
	"time"

	"github.com/defektive/xodbox/pkg/model"
)

const maxInteractionPage = 200

// interactionSummary is the list-view projection of an interaction (no heavy
// raw request/body fields).
type interactionSummary struct {
	ID            uint      `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	RemoteAddr    string    `json:"remote_addr"`
	RemotePort    string    `json:"remote_port"`
	Handler       string    `json:"handler"`
	RequestType   string    `json:"request_type"`
	RequestTarget string    `json:"request_target"`
	Protocol      string    `json:"protocol"`
	UserAgent     string    `json:"user_agent"`
}

func summarize(i model.Interaction) interactionSummary {
	return interactionSummary{
		ID:            i.ID,
		CreatedAt:     i.CreatedAt,
		RemoteAddr:    i.RemoteAddr,
		RemotePort:    i.RemotePort,
		Handler:       i.Handler,
		RequestType:   i.RequestType,
		RequestTarget: i.RequestTarget,
		Protocol:      i.Protocol,
		UserAgent:     i.UserAgent,
	}
}

// interactionDetail adds the raw request, body, and a replay curl command.
type interactionDetail struct {
	interactionSummary
	Headers string `json:"headers"`
	Body    string `json:"body"`
	Curl    string `json:"curl"`
}

func (a *adminAuth) handleInteractions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := model.InteractionFilter{
		Handler:       q.Get("handler"),
		RemoteAddr:    q.Get("remote"),
		RequestTarget: q.Get("target"),
		Limit:         atoiDefault(q.Get("limit"), 50),
		Offset:        atoiDefault(q.Get("offset"), 0),
	}
	if f.Limit > maxInteractionPage {
		f.Limit = maxInteractionPage
	}
	if f.Limit < 1 {
		f.Limit = 1
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	rows := model.QueryInteractions(f)
	items := make([]interactionSummary, 0, len(rows))
	for _, row := range rows {
		items = append(items, summarize(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"total":  model.CountInteractions(f),
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

func (a *adminAuth) handleInteraction(w http.ResponseWriter, r *http.Request) {
	i := a.lookupInteraction(w, r)
	if i == nil {
		return
	}
	writeJSON(w, http.StatusOK, interactionDetail{
		interactionSummary: summarize(*i),
		Headers:            i.Headers,
		Body:               string(i.Data),
		Curl:               interactionCurl(i),
	})
}

func (a *adminAuth) handleInteractionCurl(w http.ResponseWriter, r *http.Request) {
	i := a.lookupInteraction(w, r)
	if i == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"curl": interactionCurl(i)})
}

func (a *adminAuth) handleBots(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, model.Bots())
}

// lookupInteraction resolves the {id} path value or writes a 400/404.
func (a *adminAuth) lookupInteraction(w http.ResponseWriter, r *http.Request) *model.Interaction {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return nil
	}
	i, err := model.InteractionByID(uint(id))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return nil
	}
	return i
}

// interactionCurl builds a replay curl for HTTP interactions; other handlers
// have no meaningful curl representation.
func interactionCurl(i *model.Interaction) string {
	if i.Handler != "httpx" {
		return ""
	}
	return CurlFromInteraction(i)
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
