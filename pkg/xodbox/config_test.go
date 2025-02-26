package xodbox

import (
	"github.com/defektive/xodbox/pkg/handlers/httpx"
	"github.com/defektive/xodbox/pkg/notifiers/app_log"
	"github.com/defektive/xodbox/pkg/types"
	"reflect"
	"testing"
)

func TestConfigFile_ToConfig(t *testing.T) {
	type fields struct {
		Defaults  map[string]string
		Handlers  []map[string]string
		Notifiers []map[string]string
	}
	tests := []struct {
		name   string
		fields fields
		want   *Config
	}{
		{
			name: "default",
			fields: fields{
				Defaults: map[string]string{
					"test": "value",
				},
				Handlers: []map[string]string{
					{
						"handler":  "HTTPX",
						"listener": ":80",
					},
				},
				Notifiers: []map[string]string{
					{
						"notifier": "app_log",
					},
				},
			},
			want: &Config{
				TemplateData: map[string]string{
					"test": "value",
				},
				Handlers: []types.Handler{httpx.NewHandler(map[string]string{
					"handler":  "HTTPX",
					"listener": ":80",
				})},
				Notifiers: []types.Notifier{app_log.NewNotifier(map[string]string{
					"notifier": "app_log",
				})},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := &ConfigFile{
				Defaults:  tt.fields.Defaults,
				Handlers:  tt.fields.Handlers,
				Notifiers: tt.fields.Notifiers,
			}
			if got := conf.ToConfig(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
