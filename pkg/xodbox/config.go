package xodbox

import (
	"os"
	"path"

	"github.com/defektive/xodbox/pkg/handlers/dns"
	"github.com/defektive/xodbox/pkg/handlers/ftp"
	"github.com/defektive/xodbox/pkg/handlers/httpx"
	"github.com/defektive/xodbox/pkg/handlers/smtp"
	ssh "github.com/defektive/xodbox/pkg/handlers/ssh"
	"github.com/defektive/xodbox/pkg/handlers/tcp"
	"github.com/defektive/xodbox/pkg/notifiers/app_log"
	"github.com/defektive/xodbox/pkg/notifiers/discord"
	"github.com/defektive/xodbox/pkg/notifiers/slack"
	"github.com/defektive/xodbox/pkg/types"
	"gopkg.in/yaml.v3"
)

const ConfigFileName = "xodbox.yaml"
const DefaultNotifyFilter = "^/l"

// Config used by App for bootstrapping
type Config struct {
	TemplateData map[string]string `yaml:"template_data"`
	Handlers     []types.Handler
	Notifiers    []types.Notifier
}

// ConfigFile defines th structure of the YAML config files
// This allows us to generalize the config
type ConfigFile struct {
	Defaults  map[string]string   `yaml:"defaults"`
	Handlers  []map[string]string `yaml:"handlers"`
	Notifiers []map[string]string `yaml:"notifiers"`
}

// ToConfig creates a Config struct based on the ConfigFile
func (conf *ConfigFile) ToConfig() *Config {

	if conf.Defaults == nil {
		conf.Defaults = map[string]string{
			"notify_filter": DefaultNotifyFilter,
			"notify_string": "l",
			"server_name":   "BreakfastBot",
		}
	}

	appConfig := &Config{conf.Defaults, []types.Handler{}, []types.Notifier{}}

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

// LoadConfig creates a Config from the yaml contents in configFile
func LoadConfig(configFile string) *Config {
	conf, err := configFromFile(configFile)
	if err != nil {
		lg().Error("error reading config", "error", err)
		os.Exit(1)
	}

	return conf.ToConfig()
}

// configFromFile returns ConfigFile loaded from a file.
func configFromFile(configFile string) (*ConfigFile, error) {
	b, err := os.ReadFile(configFile)
	if err != nil {
		if ConfigFileName == configFile {
			// no file, load from self
			b, err = EmbeddedConfigReadFile(path.Join("config", ConfigFileName))
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

var newHandlerMap = map[string]func(handlerConfig map[string]string) types.Handler{}
var newNotifierMap = map[string]func(notifierConfig map[string]string) types.Notifier{}

func init() {
	newHandlerMap["DNS"] = dns.NewHandler
	newHandlerMap["HTTPX"] = httpx.NewHandler
	newHandlerMap["SSH"] = ssh.NewHandler
	newHandlerMap["SMTP"] = smtp.NewHandler
	newHandlerMap["FTP"] = ftp.NewHandler
	newHandlerMap["TCP"] = tcp.NewHandler

	newNotifierMap["app_log"] = app_log.NewNotifier
	newNotifierMap["discord"] = discord.NewNotifier
	newNotifierMap["slack"] = slack.NewNotifier
}
