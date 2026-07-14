package httpx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/analog-substance/util/cli/build_info"
	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/defektive/xodbox/pkg/util"
)

type Event struct {
	*types.BaseEvent
	req              *http.Request
	body             []byte
	requestHeader    []byte
	botExemptPrivate bool
	// interaction is a snapshot of the request built synchronously in NewEvent,
	// so the event loop can persist it without touching the live *http.Request
	// on another goroutine (which the handler may still be using or have freed).
	interaction *model.Interaction
}

func NewEvent(req *http.Request) *Event {
	body, _ := io.ReadAll(req.Body)
	defer req.Body.Close()

	dump, _ := httputil.DumpRequest(req, false) // headers only (no body)
	hostname, portNum := util.GetHostAndPortFromRequest(req)

	protocol := "http"
	if req.TLS != nil {
		protocol = "https"
	}

	ev := &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       hostname,
			RemotePortNumber: portNum,
			UserAgentString:  req.UserAgent(),
			RawData:          append(dump, body...), // full dump for notifiers
		},
		req:              req,
		body:             body,
		requestHeader:    dump, // headers only; RawRequest() appends body
		botExemptPrivate: true,
		interaction: &model.Interaction{
			RemoteAddr:    hostname,
			RemotePort:    fmt.Sprintf("%d", portNum),
			Handler:       "httpx",
			Protocol:      protocol,
			RequestType:   req.Method,
			RequestTarget: req.URL.Path,
			UserAgent:     req.UserAgent(),
			Headers:       string(dump), // headers only — body is stored in Data
			Data:          body,
		},
	}
	return ev
}

// Interaction returns the record snapshotted in NewEvent (see types.Persistable).
func (e *Event) Interaction() *model.Interaction {
	return e.interaction
}

func (e *Event) Details() string {
	return fmt.Sprintf("HTTPX: %s %s from %s", e.req.Method, e.req.URL.String(), e.req.RemoteAddr)
}

// FilterString returns "HTTPX <METHOD> <path?query> from <ip-chain>". The
// IP chain is the unique X-Forwarded-For + peer list, so filters can select
// on method, path, or any hop's source IP.
func (e *Event) FilterString() string {
	return fmt.Sprintf("HTTPX %s %s from %s",
		e.req.Method, e.req.URL.RequestURI(), strings.Join(util.RequestIPChain(e.req), ","))
}

func (e *Event) Body() []byte {
	return e.body
}

func (e *Event) RequestHeaders() []byte {
	return e.requestHeader
}

func (e *Event) RawRequest() []byte {
	return append(e.requestHeader, e.body...)
}

func (e *Event) Request() *http.Request {
	return e.req
}

func (e *Event) RemoteAddr() string {
	return e.BaseEvent.RemoteAddr
}

func (e *Event) Dispatch(cc chan types.InteractionEvent) {
	go func() {
		cc <- e
	}()
}

// NotifySuppressed reports whether notifiers should skip this event. Suspected
// bots (high request volume) are still persisted and shown in the Events log,
// but don't fire notifications — otherwise a scanner floods every notifier.
// Loopback/private sources are usually the operator or an internal SSRF
// callback, so (when enabled) they bypass volume-based bot detection.
func (e *Event) NotifySuppressed() bool {
	addr := e.BaseEvent.RemoteAddr
	exempt := e.botExemptPrivate && util.IsPrivateOrLoopback(addr)
	if !exempt && model.IsBot(addr) {
		// Debug (not Warn) and throttled per source: a bot calling many times a
		// second would otherwise emit one log line per request. The traffic is
		// still recorded; only the notification is suppressed.
		if botSuppressLog.allow(addr) {
			lg().Debug("suppressing notifiers for suspected bot (high request volume); still recorded. Set bot_exempt_private to exempt local/private sources", "remote_addr", addr)
		}
		return true
	}
	return false
}

func (e *Event) TemplateContext(templateData map[string]string) *TemplateContext {
	r := e.Request()

	remoteAddrs := []string{r.RemoteAddr}
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		remoteAddrs = append(remoteAddrs, headerIP)
	}
	headerIP = r.Header.Get("X-Real-IP")
	if headerIP != "" {
		remoteAddrs = append(remoteAddrs, headerIP)
	}

	fullRequestBytes := e.RawRequest()

	tcr := &TemplateRequestContext{
		RemoteAddr:  remoteAddrs,
		UserAgent:   r.UserAgent(),
		Host:        r.Host,
		Path:        r.URL.Path,
		FullRequest: fullRequestBytes,
		Body:        e.Body(),
		Headers:     r.Header,
		GetParams:   r.URL.Query(),
		PostParams:  r.PostForm,
	}

	for param, vals := range r.URL.Query() {
		if len(vals) > 1 {
			for idx, val := range vals {
				templateData[fmt.Sprintf("GET_%s_%d", param, idx)] = val
			}
		} else if len(vals) == 1 {
			templateData[fmt.Sprintf("GET_%s", param)] = vals[0]
		}
	}

	tc := &TemplateContext{
		Version:          build_info.GetLoadedVersion().Version,
		NotifyString:     templateData["notify_string"],
		ServerName:       templateData["server_name"],
		CallBackImageURL: fmt.Sprintf("http://%s%s?&xdbxImage", r.Host, r.RequestURI),
		CallBackURL:      fmt.Sprintf("http://%s%s?&xdbx", r.Host, r.RequestURI),
		Extra:            templateData,
		Payloads:         model.SortedPayloads(),
		Request:          tcr,
	}

	return tc

}

type TemplateContext struct {
	Version          string
	NotifyString     string
	Uptime           time.Duration
	Payloads         []model.Payload
	CallBackImageURL string
	CallBackURL      string
	Extra            map[string]string
	ProxySrv         string
	ProxySrvRegex    string

	Request    *TemplateRequestContext
	ServerName string
}

type TemplateRequestContext struct {
	RemoteAddr  []string
	Host        string
	Path        string
	UserAgent   string
	FullRequest []byte
	Body        []byte

	Headers    map[string][]string
	GetParams  map[string][]string
	PostParams map[string][]string
}

// parseRawBody captures a non-multipart, non-empty request body as an
// UploadedFile so the body can be downloaded via the Files API. It skips
// multipart/* (already handled by parseUploads) and
// application/x-www-form-urlencoded (regular HTML form data, not a file).
func parseRawBody(e *Event, maxUploadSize int64) {
	if len(e.body) == 0 {
		return
	}
	ct := e.req.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(ct)
	if strings.HasPrefix(mediaType, "multipart/") ||
		mediaType == "application/x-www-form-urlencoded" {
		return
	}
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}

	data := e.body
	if maxUploadSize > 0 && int64(len(data)) > maxUploadSize {
		data = data[:maxUploadSize]
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	f := model.UploadedFile{
		FileName:    rawBodyFilename(e.req, mediaType),
		ContentType: mediaType,
		Size:        int64(len(data)),
		ContentHash: hash,
	}
	if existing, err := model.FindFileByHash(hash); err != nil || existing == nil {
		f.Data = data
	}
	e.interaction.Files = append(e.interaction.Files, f)
}

// rawBodyFilename derives a download filename for a raw (non-multipart) body.
// Priority: Content-Disposition header → last URL path segment → "body.<ext>".
func rawBodyFilename(req *http.Request, mediaType string) string {
	if cd := req.Header.Get("Content-Disposition"); cd != "" {
		_, params, _ := mime.ParseMediaType(cd)
		if name := params["filename"]; name != "" {
			// Strip any leading path component (handles Windows \\ separators too).
			if i := strings.LastIndexAny(name, `/\`); i >= 0 {
				name = name[i+1:]
			}
			if name != "" {
				return name
			}
		}
	}
	if seg := urlPathBase(req.URL.Path); seg != "" {
		return seg
	}
	return "body" + extFromMediaType(mediaType)
}

// urlPathBase returns the last non-empty, non-root segment of a URL path.
func urlPathBase(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	return p
}

// extFromMediaType maps a MIME media type to a common file extension.
func extFromMediaType(mt string) string {
	switch mt {
	case "application/json":
		return ".json"
	case "application/xml", "text/xml":
		return ".xml"
	case "application/pdf":
		return ".pdf"
	case "text/plain":
		return ".txt"
	case "text/html":
		return ".html"
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	case "application/zip":
		return ".zip"
	case "application/gzip":
		return ".gz"
	case "application/x-tar":
		return ".tar"
	default:
		return ".bin"
	}
}

// parseUploads inspects an event's Content-Type for multipart/form-data and
// extracts file parts into e.interaction.Files. maxUploadSize limits each part
// read; 0 means no limit. Non-file form fields (no filename) are skipped.
func parseUploads(e *Event, maxUploadSize int64) {
	ct := e.req.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/") {
		return
	}
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return
	}
	boundary := params["boundary"]
	if boundary == "" {
		return
	}

	limit := int64(math.MaxInt64)
	if maxUploadSize > 0 {
		limit = maxUploadSize
	}

	mr := multipart.NewReader(bytes.NewReader(e.body), boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		if part.FileName() == "" {
			_ = part.Close()
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(part, limit))
		_ = part.Close()
		ct := part.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/octet-stream"
		}
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])

		f := model.UploadedFile{
			FileName:    part.FileName(),
			ContentType: ct,
			Size:        int64(len(data)),
			ContentHash: hash,
		}
		// Deduplicate: if we already have a file with the same content, skip the
		// BLOB and let the download handler resolve it via the hash.
		if existing, err := model.FindFileByHash(hash); err != nil || existing == nil {
			f.Data = data
		}
		e.interaction.Files = append(e.interaction.Files, f)
	}
}
