package httpx

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func newHTTPRequest(url string) *http.Request {
	r, err := http.NewRequest("DELETE", url, bytes.NewReader([]byte("pizza")))
	if err != nil {
		panic(err)
	}

	r.RemoteAddr = "127.0.0.1:56429"
	return r
}

func TestInspect(t *testing.T) {
	type args struct {
		e *Event
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantBody    []byte
		wantHeaders http.Header
	}{
		{
			name: "Should be a text response",
			args: args{
				e: NewEvent(newHTTPRequest("http://localhost/l/pizza")),
			},
			wantErr:  false,
			wantBody: []byte("Text Request\n\nDELETE /l/pizza HTTP/1.1\r\nHost: localhost\r\n\r\npizzapizza"),
			wantHeaders: http.Header{
				"Content-Type": {"text/plain; charset=utf-8"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			err := Inspect(w, tt.args.e)

			if (err != nil) != tt.wantErr {
				t.Errorf("Inspect() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(w.Body.Bytes(), tt.wantBody) {
				t.Errorf("Body got = \n%v\nwant:\n%v", w.Body.String(), string(tt.wantBody))
			}

			if !reflect.DeepEqual(w.Header(), tt.wantHeaders) {
				t.Errorf("headers got = %v\nwant  %v", w.Header(), tt.wantHeaders)
			}

		})
	}
}
