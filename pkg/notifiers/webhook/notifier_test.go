package webhook

import (
	"bytes"
	"github.com/defektive/xodbox/pkg/handlers/httpx"
	"github.com/defektive/xodbox/pkg/types"
	"net/http"
	"reflect"
	"regexp"
	"testing"
)

func newHTTPMethodRequest(method, url string) *http.Request {
	r, err := http.NewRequest(method, url, bytes.NewReader([]byte("pizza")))
	if err != nil {
		panic(err)
	}

	r.RemoteAddr = "127.0.0.1:56429"

	return r
}

func newHTTPRequest(url string) *http.Request {
	return newHTTPMethodRequest("DELETE", url)
}

func TestWebhookNotifier_Payload(t *testing.T) {
	type fields struct {
		name   string
		URL    string
		filter *regexp.Regexp
	}
	type args struct {
		e types.InteractionEvent
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Base Event",
			fields: fields{
				name:   "webhook",
				URL:    "http://pizza.nowhere/",
				filter: regexp.MustCompile(",*"),
			},
			args: args{
				&types.BaseEvent{
					RemoteAddr:       "123.456.789.2",
					RemotePortNumber: 90872,
					UserAgentString:  "dumb test event",
					RawData:          []byte("pizza"),
				},
			},
			want: []byte(`{"RemoteAddr":"123.456.789.2","RemotePort":90872,"UserAgent":"dumb test event","Data":"pizza","Details":"Default Event"}`),
		},
		{
			name: "HTTP Request",
			fields: fields{
				name:   "webhook",
				URL:    "http://pizza.nowhere/",
				filter: regexp.MustCompile(",*"),
			},
			args: args{
				httpx.NewEvent(newHTTPRequest("http://localhost/")),
			},
			want: []byte(`{"RemoteAddr":"127.0.0.1","RemotePort":56429,"UserAgent":"","Data":"DELETE / HTTP/1.1\r\nHost: localhost\r\n\r\npizza","Details":"HTTPX: DELETE http://localhost/ from 127.0.0.1:56429"}`),
		},
		{
			name: "HTTP Request with port",
			fields: fields{
				name:   "webhook",
				URL:    "http://pizza.nowhere/",
				filter: regexp.MustCompile(",*"),
			},
			args: args{
				httpx.NewEvent(newHTTPRequest("http://localhost:9090/")),
			},
			want: []byte(`{"RemoteAddr":"127.0.0.1","RemotePort":56429,"UserAgent":"","Data":"DELETE / HTTP/1.1\r\nHost: localhost:9090\r\n\r\npizza","Details":"HTTPX: DELETE http://localhost:9090/ from 127.0.0.1:56429"}`),
		},
		{
			name: "HTTPS Request with port",
			fields: fields{
				name:   "webhook",
				URL:    "http://pizza.nowhere/",
				filter: regexp.MustCompile(",*"),
			},
			args: args{
				httpx.NewEvent(newHTTPRequest("https://localhost:8443/")),
			},
			want: []byte(`{"RemoteAddr":"127.0.0.1","RemotePort":56429,"UserAgent":"","Data":"DELETE / HTTP/1.1\r\nHost: localhost:8443\r\n\r\npizza","Details":"HTTPX: DELETE https://localhost:8443/ from 127.0.0.1:56429"}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wh := &Notifier{
				name:   tt.fields.name,
				URL:    tt.fields.URL,
				filter: tt.fields.filter,
			}
			got, err := wh.Payload(tt.args.e)
			if (err != nil) != tt.wantErr {
				t.Errorf("Payload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Payload() got = %v, want %v", string(got), string(tt.want))
			}
		})
	}
}

func TestFilterMatches(t *testing.T) {
	type args struct {
		filter *regexp.Regexp
		data   string
	}

	alertPizza := httpx.NewEvent(newHTTPRequest("http://localhost:9090/alertPrefix/pizza"))
	noAlertPizza := httpx.NewEvent(newHTTPRequest("http://localhost:9090/notCorrectPrefix/pizza"))

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "DELETE /alertPrefix",
			args: args{
				filter: regexp.MustCompile("(GET|POST|HEAD|DELETE|PUT|PATCH|TRACE) /alertPrefix"),
				data:   alertPizza.Data(),
			},
			want: true,
		},
		{
			name: "DELETE /notCorrectPrefix",
			args: args{
				filter: regexp.MustCompile("(GET|POST|HEAD|DELETE|PUT|PATCH|TRACE) /alertPrefix"),
				data:   noAlertPizza.Data(),
			},
			want: false,
		},
		{
			name: "DELETE /notCorrectPrefix",
			args: args{
				filter: regexp.MustCompile("(GET|POST) /alertPrefix"),
				data:   alertPizza.Data(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterMatches(tt.args.filter, tt.args.data); got != tt.want {
				t.Errorf("FilterMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}
