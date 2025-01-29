package app

import (
	"github.com/defektive/xodbox/pkg/app/types"
	"github.com/defektive/xodbox/pkg/dns"
	"github.com/defektive/xodbox/pkg/httpx"
	"gopkg.in/yaml.v3"
	"os"
)

type ConfigFile struct {
	Handlers  []map[string]string `yaml:"handlers"`
	Notifiers []map[string]string `yaml:"notifiers"`
}

func ConfigFromFile(configFile string) (*ConfigFile, error) {
	b, err := os.ReadFile("xodbox.yaml")
	if err != nil {
		return nil, err
	}

	conf := &ConfigFile{}
	err = yaml.Unmarshal(b, conf)
	return conf, err
}

func LoadAppConfig(configFile string) *AppConfig {
	conf, err := ConfigFromFile(configFile)
	if err != nil {
		lg().Error("error reading config", "error", err)
		os.Exit(1)
	}

	return conf.ToAppConfig()
}

func (conf *ConfigFile) ToAppConfig() *AppConfig {
	appConfig := &AppConfig{[]types.Handler{}, []types.Notifier{}}
	for _, handler := range conf.Handlers {
		if handler["handler"] == "HTTPX" {
			if handler["listener"] != "" {
				h := httpx.NewHandler(handler["listener"], false)
				appConfig.Handlers = append(appConfig.Handlers, h)
			}
		}
		if handler["handler"] == "DNS" {
			if handler["listener"] != "" {

				h := dns.NewHandler(handler["listener"], handler["defaultIP"])
				appConfig.Handlers = append(appConfig.Handlers, h)
			}
		}
	}

	for _, notifier := range conf.Notifiers {
		if notifier["notifier"] == "slack" {
			n := NewSlackWebhookNotifier(notifier["url"], notifier["channel"], notifier["author"], notifier["author_image"])
			appConfig.Notifiers = append(appConfig.Notifiers, n)
			continue
		}

		if notifier["notifier"] == "discord" {
			n := NewDiscordWebhookNotifier(notifier["url"], notifier["author"], notifier["author_image"])
			appConfig.Notifiers = append(appConfig.Notifiers, n)
			continue
		}

		if notifier["notifier"] == "log" {
			n := NewLogNotifier()
			appConfig.Notifiers = append(appConfig.Notifiers, n)
			continue
		}
	}
	return appConfig
}

type AppConfig struct {
	Handlers  []types.Handler
	Notifiers []types.Notifier
}
