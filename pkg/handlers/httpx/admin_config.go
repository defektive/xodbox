package httpx

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

const maxConfigBody = 1 << 20 // 1 MiB

type configResponse struct {
	ConfigPath string              `json:"configPath"`
	Defaults   map[string]string   `json:"defaults"`
	Handlers   []map[string]string `json:"handlers"`
	Notifiers  []map[string]string `json:"notifiers"`
	Workers    []map[string]string `json:"workers"`
}

func (a *adminAuth) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	if a.configOps == nil {
		writeErr(w, http.StatusServiceUnavailable, "config management not available")
		return
	}
	cf, err := a.configOps.Read()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to read config: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, configResponse{
		ConfigPath: a.configOps.FilePath(),
		Defaults:   cf.Defaults,
		Handlers:   cf.Handlers,
		Notifiers:  cf.Notifiers,
		Workers:    cf.Workers,
	})
}

type configSchemaResponse struct {
	Handlers  []string `json:"handlers"`
	Notifiers []string `json:"notifiers"`
	Workers   []string `json:"workers"`
}

func (a *adminAuth) handleConfigSchema(w http.ResponseWriter, _ *http.Request) {
	if a.configOps == nil {
		writeErr(w, http.StatusServiceUnavailable, "config management not available")
		return
	}
	writeJSON(w, http.StatusOK, configSchemaResponse{
		Handlers:  a.configOps.HandlerNames(),
		Notifiers: a.configOps.NotifierNames(),
		Workers:   a.configOps.WorkerNames(),
	})
}

type configPutRequest struct {
	Defaults  map[string]string   `json:"defaults"`
	Handlers  []map[string]string `json:"handlers"`
	Notifiers []map[string]string `json:"notifiers"`
	Workers   []map[string]string `json:"workers"`
}

func (a *adminAuth) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	if a.configOps == nil {
		writeErr(w, http.StatusServiceUnavailable, "config management not available")
		return
	}
	var req configPutRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxConfigBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}

	cf := &types.ConfigFile{
		Defaults:  req.Defaults,
		Handlers:  req.Handlers,
		Notifiers: req.Notifiers,
		Workers:   req.Workers,
	}

	if errs := a.configOps.Validate(cf); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "validation failed",
			"errors": errs,
		})
		return
	}

	if err := a.configOps.Write(cf); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to write config: "+err.Error())
		return
	}

	reloading := a.app != nil
	writeJSON(w, http.StatusOK, map[string]any{
		"saved":     true,
		"reloading": reloading,
	})

	if reloading {
		go func() {
			time.Sleep(500 * time.Millisecond)
			if err := a.app.Reload(); err != nil {
				lg().Error("config reload after save failed", "err", err)
			}
		}()
	}
}
