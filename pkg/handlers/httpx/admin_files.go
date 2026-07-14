package httpx

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/defektive/xodbox/pkg/model"
)

// handleInteractionFiles lists the file metadata for all uploads attached to
// an interaction. Raw file data is not included; use handleInteractionFileDownload.
func (a *adminAuth) handleInteractionFiles(w http.ResponseWriter, r *http.Request) {
	i := a.lookupInteraction(w, r)
	if i == nil {
		return
	}
	rawFiles := model.FilesForInteraction(i.ID)
	out := make([]fileInfo, 0, len(rawFiles))
	for _, f := range rawFiles {
		out = append(out, toFileInfo(f))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleInteractionFileDownload serves the raw bytes of a single uploaded file.
// The file must belong to the interaction named in the URL to prevent IDOR.
func (a *adminAuth) handleInteractionFileDownload(w http.ResponseWriter, r *http.Request) {
	interactionID, ok := pathID(w, r)
	if !ok {
		return
	}
	fileID, ok := pathUintNamed(w, r, "fileID")
	if !ok {
		return
	}

	f, err := model.UploadedFileByID(fileID)
	if err != nil || f.InteractionID != interactionID {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}

	// Deduped file: Data is nil; resolve the bytes from the canonical copy.
	if len(f.Data) == 0 && f.ContentHash != "" {
		canonical, cerr := model.FindFileByHash(f.ContentHash)
		if cerr != nil || canonical == nil {
			writeErr(w, http.StatusNotFound, "file data not found")
			return
		}
		f.Data = canonical.Data
	}

	ct := f.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, f.FileName))
	h.Set("Content-Length", strconv.FormatInt(f.Size, 10))
	_, _ = w.Write(f.Data)
}

// handleSinkFiles lists all uploaded files across interactions attributed to
// the given sink slug, newest first. Paginated via ?limit= and ?offset=.
func (a *adminAuth) handleSinkFiles(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
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

	files, total := model.SinkFiles(slug, limit, offset)
	out := make([]fileInfo, 0, len(files))
	for _, f := range files {
		out = append(out, toFileInfo(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  out,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// pathUintNamed parses a named path value as uint, writing a 400 on error.
func pathUintNamed(w http.ResponseWriter, r *http.Request, name string) (uint, bool) {
	id, err := strconv.ParseUint(r.PathValue(name), 10, strconv.IntSize)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return uint(id), true
}
