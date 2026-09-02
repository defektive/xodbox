package httpx

import (
	"errors"
	"net/http"

	"github.com/defektive/xodbox/pkg/types"
)

// handleWorkers lists the configured background jobs and the outcome of each
// one's most recent run, so an operator can tell a job that ran and found
// nothing to do apart from one that was never scheduled.
func (a *adminAuth) handleWorkers(w http.ResponseWriter, _ *http.Request) {
	if a.app == nil {
		writeErr(w, http.StatusServiceUnavailable, "worker management not available")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"workers": a.app.WorkerStatus()})
}

// handleRunWorker triggers an out-of-schedule run. It replies 202 as soon as
// the run is accepted: a purge that vacuums a large database can take minutes,
// far longer than a request should be held open. The caller polls
// GET /api/workers for the result.
func (a *adminAuth) handleRunWorker(w http.ResponseWriter, r *http.Request) {
	if a.app == nil {
		writeErr(w, http.StatusServiceUnavailable, "worker management not available")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "missing worker name")
		return
	}

	switch err := a.app.TriggerWorker(name); {
	case err == nil:
	case errors.Is(err, types.ErrUnknownWorker):
		writeErr(w, http.StatusNotFound, "no worker named "+name+" is configured")
		return
	case errors.Is(err, types.ErrWorkerBusy):
		writeErr(w, http.StatusConflict, "worker "+name+" is already running")
		return
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"started": true,
		"worker":  name,
	})
}
