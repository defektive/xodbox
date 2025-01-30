package httpx

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/app/types"
	"html"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Handler struct {
	name     string
	Listener string
	AutoCert bool

	dispatchChannel chan types.InteractionEvent
}

func NewHandler(listener string, autoCert bool) *Handler {
	return &Handler{
		name:     "HTTPX",
		Listener: listener,
		AutoCert: autoCert,
	}
}

type Event struct {
	*types.BaseEvent
	req *http.Request
}

func newHTTPEvent(req *http.Request) types.InteractionEvent {
	remoteAddrURL := fmt.Sprintf("http://%s", req.RemoteAddr)
	parsedURL, _ := url.Parse(remoteAddrURL)
	portNum, _ := strconv.Atoi(parsedURL.Port())
	dump, _ := httputil.DumpRequest(req, true)

	return &Event{
		BaseEvent: &types.BaseEvent{
			RemoteAddr:       parsedURL.Hostname(),
			RemotePortNumber: portNum,
			UserAgentString:  req.UserAgent(),
			RawData:          dump,
		},
		req: req,
	}
}

func (e *Event) Details() string {
	return fmt.Sprintf("HTTPX: %s %s://%s%s from %s", e.req.Method, "http", e.req.Host, e.req.URL.String(), e.req.RemoteAddr)
}

func (h *Handler) dispatchEvent(r *http.Request) {
	h.dispatchChannel <- newHTTPEvent(r)
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Start(eventChan chan types.InteractionEvent) error {
	h.dispatchChannel = eventChan

	mux := &http.ServeMux{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		go h.dispatchEvent(r)

		rr := NewRequestResponse(r)
		lineHeight := 15
		characterWidth := 7

		if strings.HasSuffix(r.URL.Path, ".png") || strings.HasSuffix(r.URL.Path, ".gif") || strings.HasSuffix(r.URL.Path, ".jpg") {
			resData := strings.Split(rr.Text(), "\n")
			maxLen := 0
			for _, v := range resData {
				ml := len(v)
				if ml > maxLen {
					maxLen = ml
				}
			}

			img := image.NewCMYK(image.Rect(0, 0, (2*lineHeight)+(maxLen*characterWidth), (2*lineHeight)+(len(resData)*lineHeight)))
			draw.Draw(img, img.Bounds(), &image.Uniform{color.White}, image.ZP, draw.Src)
			for i, v := range resData {
				addLabel(img, lineHeight, (i*lineHeight)+30, v)
			}

			var err error

			if strings.HasSuffix(r.URL.Path, ".png") {
				w.Header().Set("Content-Type", "image/png")
				err = png.Encode(w, img)
			}

			if strings.HasSuffix(r.URL.Path, ".gif") {
				w.Header().Set("Content-Type", "image/gif")
				err = gif.Encode(w, img, &gif.Options{NumColors: 256})
			}

			if strings.HasSuffix(r.URL.Path, ".jpg") {
				w.Header().Set("Content-Type", "image/jpeg")
				err = jpeg.Encode(w, img, &jpeg.Options{Quality: 80})
			}

			if err != nil {
				lg().Error("error encoding image", "err", err)
			} else {
				return
			}
		}

		if false && r.URL.Path == "/wpad.dat" {
			script := strings.ReplaceAll(WPAD_SCRIPT, "ProxySrvRegex", "18\\.224\\.69\\.163")
			script = strings.ReplaceAll(script, "ProxySrv", "18.224.69.163")
			fmt.Fprint(w, script)
			return
		}

		if strings.HasSuffix(r.URL.Path, ".html") || strings.HasSuffix(r.URL.Path, ".htm") {

			w.Header().Set("Content-Type", "text/html; charset=utf-8")

			htmlRes := fmt.Sprintf("<html><head></head><body><h1>HTML Request</h1><pre>%s</pre></body></html>", html.EscapeString(rr.Text()))
			fmt.Fprint(w, htmlRes)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, fmt.Sprintf("Text Request\n\n%s", rr.Text()))

		//io.WriteString(w, htmlIndex)
	})

	httpSrv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}

	httpSrv.Addr = h.Listener

	lg().Info("Starting HTTP server", "listener", h.Listener)
	err := httpSrv.ListenAndServe()
	if err != nil {
		lg().Error("error starting HTTP server", "listener", h.Listener, "err", err)
		return err
	}
	return nil
}
