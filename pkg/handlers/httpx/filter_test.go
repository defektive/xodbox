package httpx

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

func TestFilterStringWithForwardedChain(t *testing.T) {
	req := &http.Request{
		Method:     "POST",
		URL:        &url.URL{Path: "/x/beacon", RawQuery: "id=1"},
		RemoteAddr: "10.0.0.1:5000",
		Header:     http.Header{},
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.2")

	e := &Event{BaseEvent: &types.BaseEvent{}, req: req}

	want := "HTTPX POST /x/beacon?id=1 from 203.0.113.9,198.51.100.2,10.0.0.1"
	if got := e.FilterString(); got != want {
		t.Errorf("FilterString =\n  %q\nwant\n  %q", got, want)
	}
}
