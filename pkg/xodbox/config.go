package xodbox

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/defektive/xodbox/pkg/handlers/dns"
	"github.com/defektive/xodbox/pkg/handlers/ftp"
	"github.com/defektive/xodbox/pkg/handlers/httpx"
	"github.com/defektive/xodbox/pkg/handlers/smb"
	"github.com/defektive/xodbox/pkg/handlers/smtp"
	ssh "github.com/defektive/xodbox/pkg/handlers/ssh"
	"github.com/defektive/xodbox/pkg/handlers/tcp"
	"github.com/defektive/xodbox/pkg/notifiers/app_log"
	"github.com/defektive/xodbox/pkg/notifiers/discord"
	"github.com/defektive/xodbox/pkg/notifiers/slack"
	"github.com/defektive/xodbox/pkg/notifiers/webhook"
	"github.com/defektive/xodbox/pkg/types"
	"github.com/defektive/xodbox/pkg/workers/purge"
	"gopkg.in/yaml.v3"
)

const ConfigFileName = "xodbox.yaml"
const DefaultNotifyFilter = "^/l"

// ConfigFilePath is the path to the active config file, set by LoadConfig.
var ConfigFilePath string

// ConfigFile is an alias for types.ConfigFile kept for backward compatibility
// within this package and its tests.
type ConfigFile = types.ConfigFile

// Config used by App for bootstrapping
type Config struct {
	TemplateData map[string]string `yaml:"template_data"`
	Handlers     []types.Handler
	Notifiers    []types.Notifier
	Workers      []types.Worker
}

// ToConfig creates a Config struct based on the ConfigFile
func ToConfig(conf *ConfigFile) *Config {

	if conf.Defaults == nil {
		conf.Defaults = map[string]string{
			"notify_filter": DefaultNotifyFilter,
			"notify_string": "l",
			"server_name":   "BreakfastBot",
		}
	}

	appConfig := &Config{conf.Defaults, []types.Handler{}, []types.Notifier{}, []types.Worker{}}

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

	for _, workerConfig := range conf.Workers {
		if newWorkerFn, ok := newWorkerMap[workerConfig["worker"]]; ok {
			appConfig.Workers = append(appConfig.Workers, newWorkerFn(workerConfig))
		} else {
			lg().Error("worker not found", "worker", workerConfig["worker"])
		}
	}

	return appConfig
}

// LoadConfig creates a Config from the yaml contents in configFile
func LoadConfig(configFile string) *Config {
	ConfigFilePath = configFile
	conf, err := ConfigFromFile(configFile)
	if err != nil {
		lg().Error("error reading config", "error", err)
		os.Exit(1)
	}

	return ToConfig(conf)
}

// ConfigFromFile returns ConfigFile loaded from a file.
func ConfigFromFile(configFile string) (*ConfigFile, error) {
	// #nosec G304 -- configFile comes from the --config flag.
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
var newWorkerMap = map[string]func(workerConfig map[string]string) types.Worker{}

func init() {
	newHandlerMap["DNS"] = dns.NewHandler
	newHandlerMap["HTTPX"] = httpx.NewHandler
	newHandlerMap["SSH"] = ssh.NewHandler
	newHandlerMap["SMTP"] = smtp.NewHandler
	newHandlerMap["FTP"] = ftp.NewHandler
	newHandlerMap["TCP"] = tcp.NewHandler
	newHandlerMap["SMB"] = smb.NewHandler

	newNotifierMap["app_log"] = app_log.NewNotifier
	newNotifierMap["discord"] = discord.NewNotifier
	newNotifierMap["slack"] = slack.NewNotifier
	newNotifierMap["webhook"] = webhook.NewNotifierFromConfig

	newWorkerMap["purge"] = purge.NewWorker
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func ValidHandlerNames() []string  { return sortedKeys(newHandlerMap) }
func ValidNotifierNames() []string { return sortedKeys(newNotifierMap) }
func ValidWorkerNames() []string   { return sortedKeys(newWorkerMap) }

// ValidateConfigFile checks that every handler, notifier, and worker entry
// references a registered name. It returns a slice of human-readable errors
// (empty when valid).
func ValidateConfigFile(cf *ConfigFile) []string {
	var errs []string
	for i, h := range cf.Handlers {
		name := h["handler"]
		if name == "" {
			errs = append(errs, fmt.Sprintf("handlers[%d]: missing \"handler\" key", i))
			continue
		}
		if _, ok := newHandlerMap[name]; !ok {
			errs = append(errs, fmt.Sprintf("handlers[%d]: unknown handler %q", i, name))
		}
	}
	for i, n := range cf.Notifiers {
		name := n["notifier"]
		if name == "" {
			errs = append(errs, fmt.Sprintf("notifiers[%d]: missing \"notifier\" key", i))
			continue
		}
		if _, ok := newNotifierMap[name]; !ok {
			errs = append(errs, fmt.Sprintf("notifiers[%d]: unknown notifier %q", i, name))
		}
	}
	for i, w := range cf.Workers {
		name := w["worker"]
		if name == "" {
			errs = append(errs, fmt.Sprintf("workers[%d]: missing \"worker\" key", i))
			continue
		}
		if _, ok := newWorkerMap[name]; !ok {
			errs = append(errs, fmt.Sprintf("workers[%d]: unknown worker %q", i, name))
		}
	}
	return errs
}

// WriteConfigFile marshals cf to YAML and writes it atomically to path.
func WriteConfigFile(p string, cf *ConfigFile) error {
	b, err := yaml.Marshal(cf)
	if err != nil {
		return err
	}

	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, ".xodbox-config-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, p)
}

// configOps implements types.ConfigOps using the package-level state.
type configOps struct{}

func (configOps) FilePath() string                       { return ConfigFilePath }
func (configOps) Read() (*types.ConfigFile, error)       { return ConfigFromFile(ConfigFilePath) }
func (configOps) Write(cf *types.ConfigFile) error       { return WriteConfigFile(ConfigFilePath, cf) }
func (configOps) Validate(cf *types.ConfigFile) []string { return ValidateConfigFile(cf) }
func (configOps) HandlerNames() []string                 { return ValidHandlerNames() }
func (configOps) NotifierNames() []string                { return ValidNotifierNames() }
func (configOps) WorkerNames() []string                  { return ValidWorkerNames() }

// NewConfigOps returns a types.ConfigOps backed by the package-level config state.
func NewConfigOps() types.ConfigOps { return configOps{} }
