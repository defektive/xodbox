package app

import (
	"github.com/defektive/xodbox/pkg/app/types"
	"github.com/defektive/xodbox/pkg/handlers/dns"
	"github.com/defektive/xodbox/pkg/handlers/httpx"
	"github.com/defektive/xodbox/pkg/notifiers/app_log"
	"github.com/defektive/xodbox/pkg/notifiers/discord"
	"github.com/defektive/xodbox/pkg/notifiers/slack"
	"github.com/defektive/xodbox/pkg/static"
	"gopkg.in/yaml.v3"
	"os"
	"path"
)

const ConfigFileName = "xodbox.yaml"
const DefaultNotifyFilter = "^/l"

type ConfigFile struct {
	Defaults  map[string]string   `yaml:"defaults"`
	Handlers  []map[string]string `yaml:"handlers"`
	Notifiers []map[string]string `yaml:"notifiers"`
}

func ConfigFromFile(configFile string) (*ConfigFile, error) {
	b, err := os.ReadFile(configFile)
	if err != nil {
		if ConfigFileName == configFile {
			// no file, load from self
			b, err = static.ReadFile(path.Join("config", ConfigFileName))
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	conf := &ConfigFile{}
	err = yaml.Unmarshal(b, conf)
	return conf, err
}

func LoadApp(configFile string) *AppConfig {
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

	if conf.Defaults == nil {
		conf.Defaults = map[string]string{
			"NotifyFilter": DefaultNotifyFilter,
		}
	}

	appConfig := &AppConfig{conf.Defaults, []types.Handler{}, []types.Notifier{}}

	for _, handlerConfig := range conf.Handlers {
		if newHandlerFn, ok := newHandlerMap[handlerConfig["handler"]]; ok {
			appConfig.Handlers = append(appConfig.Handlers, newHandlerFn(handlerConfig))
		} else {
			lg().Error("handler not found", "handler", handlerConfig["handler"])
		}
	}

	for _, notifierConfig := range conf.Notifiers {
		if newNotifierFn, ok := newNotifierMap[notifierConfig["notifier"]]; ok {
			appConfig.Notifiers = append(appConfig.Notifiers, newNotifierFn(notifierConfig))
		} else {
			lg().Error("notifier not found", "notifier", notifierConfig["notifier"])
		}
	}
	return appConfig
}

type AppConfig struct {
	TemplateData map[string]string `yaml:"template_data"`
	Handlers     []types.Handler
	Notifiers    []types.Notifier
}
