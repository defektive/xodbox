package httpx

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/defektive/xodbox/pkg/model"
)

// streamFilter mirrors the request-log and sink filters so a browser can
// subscribe to exactly the slice it is viewing. handler/remote/target are exact
// matches (like the request log); sink is a substring match on the target or
// raw headers (like the sink view).
type streamFilter struct {
	handler string
	remote  string
	target  string
	sink    string
}

func (f streamFilter) matches(i *model.Interaction) bool {
	if f.handler != "" && i.Handler != f.handler {
		return false
	}
	if f.remote != "" && i.RemoteAddr != f.remote {
		return false
	}
	if f.target != "" && i.RequestTarget != f.target {
		return false
	}
	if f.sink != "" &&
		!strings.Contains(i.RequestTarget, f.sink) &&
		!strings.Contains(i.Headers, f.sink) {
		return false
	}
	return true
}

// handleStream serves a Server-Sent Events stream of newly captured
// interactions (optionally filtered), so the request log and sink views update
// in real time. Auth is the session cookie (EventSource can't set headers),
// which requireAuth accepts.
func (a *adminAuth) handleStream(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := streamFilter{
		handler: q.Get("handler"),
		remote:  q.Get("remote"),
		target:  q.Get("target"),
		sink:    q.Get("sink"),
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering

	// Clear the server's WriteTimeout for this long-lived response so the
	// stream isn't cut off; keep-alive pings still detect dead clients.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	events, cancel := model.SubscribeInteractions()
	defer cancel()

	// Open the stream and suggest a client reconnect backoff.
	fmt.Fprint(w, "retry: 3000\n: connected\n\n")
	_ = rc.Flush()

	ctx := r.Context()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		case i, ok := <-events:
			if !ok {
				return
			}
			if !filter.matches(i) {
				continue
			}
			data, err := json.Marshal(summarize(*i))
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: interaction\ndata: %s\n\n", data); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}
