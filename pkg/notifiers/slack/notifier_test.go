package slack

import (
	"bytes"
	"github.com/defektive/xodbox/pkg/handlers/httpx"
	"github.com/defektive/xodbox/pkg/notifiers/webhook"
	"github.com/defektive/xodbox/pkg/types"
	"net/http"
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

func TestSlackNotifier_Payload(t *testing.T) {
	type fields struct {
		Notifier *webhook.Notifier
		User     string
		Icon     string
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
				Notifier: &webhook.Notifier{},
				User:     "user",
				Icon:     "icon",
			},
			args: args{
				types.NewEvent(
					"123.456.789.2",
					90872,
					"dumb test event",
					[]byte("pizza"),
				),
			},
			want: []byte(`{"channel":"","username":"user","icon_emoji":"icon","text":"Base Event\n` + "```pizza\\n```" + `"}`),
		},
		{
			name: "HTTP Request",
			fields: fields{
				Notifier: &webhook.Notifier{},
				User:     "user",
				Icon:     "icon",
			},
			args: args{
				httpx.NewEvent(newHTTPRequest("http://localhost/")),
			},
			want: []byte(`{"channel":"","username":"user","icon_emoji":"icon","text":"HTTPX: DELETE http://localhost/ from 127.0.0.1:56429\n` + "```" + `DELETE / HTTP/1.1\r\nHost: localhost\r\n\r\npizza\n` + "```" + `"}`),
		},
		{
			name: "HTTP Request with port",
			fields: fields{
				Notifier: &webhook.Notifier{},
				User:     "user",
				Icon:     "icon",
			},
			args: args{
				httpx.NewEvent(newHTTPRequest("http://localhost:9090/")),
			},
			want: []byte(`{"channel":"","username":"user","icon_emoji":"icon","text":"HTTPX: DELETE http://localhost:9090/ from 127.0.0.1:56429\n` + "```" + `DELETE / HTTP/1.1\r\nHost: localhost:9090\r\n\r\npizza\n` + "```" + `"}`),
		},
		{
			name: "HTTPS Request with port",
			fields: fields{
				Notifier: &webhook.Notifier{},
				User:     "user",
				Icon:     "icon",
			},
			args: args{
				httpx.NewEvent(newHTTPRequest("https://localhost:8443/")),
			},
			want: []byte(`{"channel":"","username":"user","icon_emoji":"icon","text":"HTTPX: DELETE https://localhost:8443/ from 127.0.0.1:56429\n` + "```" + `DELETE / HTTP/1.1\r\nHost: localhost:8443\r\n\r\npizza\n` + "```" + `"}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wh := &Notifier{
				Notifier: tt.fields.Notifier,
				User:     tt.fields.User,
				Icon:     tt.fields.Icon,
			}
			got, err := wh.Payload(tt.args.e)
			if (err != nil) != tt.wantErr {
				t.Errorf("Payload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Payload() got = %v\nwant  %v", string(got), string(tt.want))
			}
		})
	}
}
