package app_log

import (
	"bytes"
	"github.com/defektive/xodbox/pkg/handlers/httpx"
	"github.com/defektive/xodbox/pkg/types"
	"net/http"
	"reflect"
	"regexp"
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

func TestNotifier_Payload(t *testing.T) {
	type fields struct {
		filter *regexp.Regexp
	}
	type args struct {
		e types.InteractionEvent
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
		want1  []any
	}{
		{
			name: "simple test",
			fields: fields{
				filter: regexp.MustCompile(".*"),
			},
			args: args{
				e: httpx.NewEvent(newHTTPRequest("http://localhost/test")),
			},
			want: "InteractionEvent received",
			want1: []any{
				"details",
				"HTTPX: DELETE http://localhost/test from 127.0.0.1:56429",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wh := &Notifier{
				filter: tt.fields.filter,
			}
			got, got1 := wh.Payload(tt.args.e)
			if got != tt.want {
				t.Errorf("Payload() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("Payload() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
