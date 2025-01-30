package app

import (
	"github.com/defektive/xodbox/pkg/app/types"
	"github.com/defektive/xodbox/pkg/handlers/dns"
	"github.com/defektive/xodbox/pkg/handlers/httpx"
	"github.com/defektive/xodbox/pkg/notifiers/app_log"
	"github.com/defektive/xodbox/pkg/notifiers/discord"
	"github.com/defektive/xodbox/pkg/notifiers/slack"
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

var newHandlerMap = map[string]func(handlerConfig map[string]string) types.Handler{}
var newNotifierMap = map[string]func(notifierConfig map[string]string) types.Notifier{}

func init() {
	newHandlerMap["DNS"] = dns.NewHandler
	newHandlerMap["HTTPX"] = httpx.NewHandler

	newNotifierMap["app_log"] = app_log.NewNotifier
	newNotifierMap["discord"] = discord.NewNotifier
	newNotifierMap["slack"] = slack.NewNotifier
}

func (conf *ConfigFile) ToAppConfig() *AppConfig {
	appConfig := &AppConfig{[]types.Handler{}, []types.Notifier{}}

	for _, handlerConfig := range conf.Handlers {
		if newHandlerFn, ok := newHandlerMap[handlerConfig["handler"]]; ok {
			appConfig.Handlers = append(appConfig.Handlers, newHandlerFn(handlerConfig))
		}
	}

	for _, notifierConfig := range conf.Notifiers {
		if newNotifierFn, ok := newNotifierMap[notifierConfig["notifier"]]; ok {
			appConfig.Notifiers = append(appConfig.Notifiers, newNotifierFn(notifierConfig))
		}
	}
	return appConfig
}

type AppConfig struct {
	Handlers  []types.Handler
	Notifiers []types.Notifier
}
