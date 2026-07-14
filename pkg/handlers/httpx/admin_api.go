package httpx

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

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

// fileInfo is the metadata-only view of an uploaded file (no raw Data blob).
type fileInfo struct {
	ID            uint      `json:"id"`
	InteractionID uint      `json:"interaction_id"`
	FileName      string    `json:"file_name"`
	ContentType   string    `json:"content_type"`
	Size          int64     `json:"size"`
	CreatedAt     time.Time `json:"created_at"`
}

func toFileInfo(f model.UploadedFile) fileInfo {
	return fileInfo{
		ID:            f.ID,
		InteractionID: f.InteractionID,
		FileName:      f.FileName,
		ContentType:   f.ContentType,
		Size:          f.Size,
		CreatedAt:     f.CreatedAt,
	}
}

// interactionDetail adds the raw request, body, and a replay curl command.
type interactionDetail struct {
	interactionSummary
	Headers       string     `json:"headers"`
	Body          string     `json:"body"`
	HasBinaryBody bool       `json:"has_binary_body"`
	Curl          string     `json:"curl"`
	Files         []fileInfo `json:"files"`
}

const maxBodyDisplay = 4096

// safeBodyString converts raw body bytes to a string safe for JSON / browser
// display. Valid UTF-8 is returned up to maxBodyDisplay bytes. Binary data is
// rendered as a hex dump of the first 512 bytes followed by a notice.
func safeBodyString(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	if utf8.Valid(data) {
		if len(data) > maxBodyDisplay {
			return string(data[:maxBodyDisplay]) + "\n[truncated — download full body via the Files tab]", false
		}
		return string(data), false
	}
	preview := data
	if len(preview) > 512 {
		preview = preview[:512]
	}
	return hex.Dump(preview) + "\n[binary body — download via the Files tab]", true
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

// toDetail builds the full detail view (raw request, body, replay curl) for an
// interaction. Curl is empty for non-httpx handlers (nothing to replay).
func toDetail(i *model.Interaction) interactionDetail {
	body, isBinary := safeBodyString(i.Data)
	rawFiles := model.FilesForInteraction(i.ID)
	files := make([]fileInfo, 0, len(rawFiles))
	for _, f := range rawFiles {
		files = append(files, toFileInfo(f))
	}
	return interactionDetail{
		interactionSummary: summarize(*i),
		Headers:            i.Headers,
		Body:               body,
		HasBinaryBody:      isBinary,
		Curl:               interactionCurl(i),
		Files:              files,
	}
}

func (a *adminAuth) handleInteraction(w http.ResponseWriter, r *http.Request) {
	i := a.lookupInteraction(w, r)
	if i == nil {
		return
	}
	writeJSON(w, http.StatusOK, toDetail(i))
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
	id, ok := pathID(w, r)
	if !ok {
		return nil
	}
	i, err := model.InteractionByID(id)
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
