package httpx

import (
	"net/http"
)

type HTTPPayload interface {
	ShouldHandle(r *http.Request) bool
	Process(w http.ResponseWriter, r *http.Request)
}

var payloads = []HTTPPayload{}

func init() {
	payloads = append(payloads, &BreakfastBot{})
	payloads = append(payloads, &RequestReflectionPayload{})

	initSimplePayloads()
}

type BreakfastBot struct {
}

func (h *BreakfastBot) ShouldHandle(r *http.Request) bool {
	return true
}

func (h *BreakfastBot) Process(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "BreakfastBot/1.9.420")
}
