package httpx

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/defektive/xodbox/pkg/types"
)

const maxConfigBody = 1 << 20 // 1 MiB

type configResponse struct {
	ConfigPath string              `json:"configPath"`
	Defaults   map[string]string   `json:"defaults"`
	Handlers   []map[string]string `json:"handlers"`
	Notifiers  []map[string]string `json:"notifiers"`
	Workers    []map[string]string `json:"workers"`
}

func (a *adminAuth) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	if a.configOps == nil {
		writeErr(w, http.StatusServiceUnavailable, "config management not available")
		return
	}
	cf, err := a.configOps.Read()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to read config: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, configResponse{
		ConfigPath: a.configOps.FilePath(),
		Defaults:   cf.Defaults,
		Handlers:   cf.Handlers,
		Notifiers:  cf.Notifiers,
		Workers:    cf.Workers,
	})
}

type fieldMeta struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Default     string `json:"default,omitempty"`
	Group       string `json:"group,omitempty"`
	Sensitive   bool   `json:"sensitive,omitempty"`
}

type typeMeta struct {
	Fields []fieldMeta `json:"fields"`
}

type configSchemaResponse struct {
	Handlers  []string            `json:"handlers"`
	Notifiers []string            `json:"notifiers"`
	Workers   []string            `json:"workers"`
	Fields    map[string]typeMeta `json:"fields"`
	Defaults  []fieldMeta         `json:"defaultFields"`
}

//nolint:funlen // field metadata table
func buildFieldSchema() (map[string]typeMeta, []fieldMeta) {
	fields := map[string]typeMeta{
		"HTTPX": {Fields: []fieldMeta{
			{Key: "listener", Label: "Listener", Description: "Bind address (e.g. :80 or 0.0.0.0:8080)", Required: true, Group: "General"},
			{Key: "static_dir", Label: "Static directory", Description: "Directory for static files served at /static/", Group: "General"},
			{Key: "payload_dir", Label: "Payload directory", Description: "Directory of payload template files", Group: "General"},
			{Key: "public_url", Label: "Public URL", Description: "Externally-reachable base URL for copy-link feature", Group: "General"},
			{Key: "max_upload_size", Label: "Max upload size", Description: "Per-file size cap in bytes (0 = no limit)", Group: "General"},
			{Key: "ui_path", Label: "Admin UI path", Description: "URL path prefix for the web UI (empty = disabled)", Group: "Admin UI"},
			{Key: "ui_allow_cidrs", Label: "Admin UI allowed CIDRs", Description: "Comma-separated CIDRs restricting admin UI access", Group: "Admin UI"},
			{Key: "admin_listener", Label: "Admin listener", Description: "Isolated bind address for admin UI (e.g. 127.0.0.1:9091)", Group: "Admin UI"},
			{Key: "notify_logins", Label: "Notify on login", Description: "Emit interaction events on admin UI logins", Group: "Admin UI"},
			{Key: "bot_exempt_private", Label: "Exempt private IPs from bot detection", Description: "Exempt loopback/private/link-local IPs from bot detection", Default: "true", Group: "Bot Detection"},
			{Key: "tls_names", Label: "TLS domain names", Description: "Comma-separated domains for automatic TLS via ACME", Group: "TLS / ACME"},
			{Key: "acme_email", Label: "ACME email", Description: "Email for certificate registration", Group: "TLS / ACME"},
			{Key: "acme_accept", Label: "Accept ACME TOS", Description: "Set to true to accept ACME terms of service", Group: "TLS / ACME"},
			{Key: "acme_url", Label: "ACME directory URL", Description: "ACME directory URL (e.g. Let's Encrypt staging)", Group: "TLS / ACME"},
			{Key: "dns_provider", Label: "DNS provider", Description: "DNS provider for ACME DNS-01 challenges (namecheap or route53)", Group: "TLS / ACME"},
			{Key: "dns_provider_api_user", Label: "DNS provider API user", Description: "API username for the DNS provider", Group: "TLS / ACME"},
			{Key: "dns_provider_api_key", Label: "DNS provider API key", Description: "API key for the DNS provider", Sensitive: true, Group: "TLS / ACME"},
			{Key: "oidc_issuer", Label: "Issuer URL", Description: "OIDC provider discovery URL (e.g. https://accounts.google.com)", Group: "OIDC / SSO"},
			{Key: "oidc_client_id", Label: "Client ID", Description: "OAuth2 client ID from your identity provider", Group: "OIDC / SSO"},
			{Key: "oidc_client_secret", Label: "Client secret", Description: "OAuth2 client secret (optional for PKCE-only flows)", Sensitive: true, Group: "OIDC / SSO"},
			{Key: "oidc_redirect_url", Label: "Redirect URL", Description: "Callback URL registered with the IdP (auto-derived if empty)", Group: "OIDC / SSO"},
			{Key: "oidc_scopes", Label: "Scopes", Description: "Comma-separated OIDC scopes", Default: "openid,profile,email", Group: "OIDC / SSO"},
			{Key: "oidc_default_role", Label: "Default role", Description: "Role for new OIDC users (user or admin)", Default: "user", Group: "OIDC / SSO"},
			{Key: "oidc_groups_claim", Label: "Groups claim", Description: "ID-token claim for group membership", Default: "groups", Group: "OIDC / SSO"},
			{Key: "oidc_admin_group", Label: "Admin group", Description: "Group value that grants the admin role", Group: "OIDC / SSO"},
			{Key: "oidc_button_label", Label: "SSO button label", Description: "Label shown on the login page SSO button", Default: "Sign in with SSO", Group: "OIDC / SSO"},
			{Key: "mdaas_log_level", Label: "MDaaS log level", Description: "Log level for payload builder", Group: "MDaaS"},
			{Key: "mdaas_bind_listener", Label: "MDaaS listener", Description: "Bind address for MDaaS builder", Group: "MDaaS"},
			{Key: "mdaas_allowed_cidr", Label: "MDaaS allowed CIDR", Description: "CIDR allowed to access MDaaS", Group: "MDaaS"},
			{Key: "mdaas_notify_url", Label: "MDaaS notify URL", Description: "Notification URL for MDaaS builds", Group: "MDaaS"},
		}},
		"DNS": {Fields: []fieldMeta{
			{Key: "listener", Label: "Listener", Description: "Bind address for the UDP DNS server (e.g. :53)", Required: true},
			{Key: "default_ip", Label: "Default IP", Description: "IPv4 address returned in A-record answers", Required: true},
		}},
		"FTP": {Fields: []fieldMeta{
			{Key: "listener", Label: "Listener", Description: "Bind address for the FTP server", Required: true},
			{Key: "server_name", Label: "Server name", Description: "Banner name shown to FTP clients", Default: "FTP Server"},
			{Key: "fake_dir_tree", Label: "Fake directory tree", Description: "Comma-separated directory paths for in-memory filesystem"},
		}},
		"SMTP": {Fields: []fieldMeta{
			{Key: "listener", Label: "Listener", Description: "Bind address for the SMTP server", Required: true},
		}},
		"SSH": {Fields: []fieldMeta{
			{Key: "listener", Label: "Listener", Description: "Bind address for the SSH server", Default: ":22"},
		}},
		"TCP": {Fields: []fieldMeta{
			{Key: "listener", Label: "Listener", Description: "Bind address for the TCP server", Required: true},
		}},
		"SMB": {Fields: []fieldMeta{
			{Key: "listener", Label: "Listener", Description: "Bind address for the SMB server", Default: ":445"},
			{Key: "target_name", Label: "Target name", Description: "NetBIOS/DNS name in NTLM challenges"},
		}},
		"app_log": {Fields: []fieldMeta{
			{Key: "filter", Label: "Filter", Description: "Regex filter — only matching events are logged", Default: ".*"},
		}},
		"discord": {Fields: []fieldMeta{
			{Key: "url", Label: "Webhook URL", Description: "Discord webhook URL", Required: true},
			{Key: "author", Label: "Author name", Description: "Username displayed on the message"},
			{Key: "author_image", Label: "Author image", Description: "Avatar URL for the message"},
			{Key: "filter", Label: "Filter", Description: "Regex filter — only matching events are sent", Default: ".*"},
		}},
		"slack": {Fields: []fieldMeta{
			{Key: "url", Label: "Webhook URL", Description: "Slack webhook URL", Required: true},
			{Key: "channel", Label: "Channel", Description: "Slack channel to post to"},
			{Key: "author", Label: "Author name", Description: "Username displayed on the message"},
			{Key: "author_image", Label: "Author icon", Description: "Emoji icon (e.g. :pirate:)"},
			{Key: "filter", Label: "Filter", Description: "Regex filter — only matching events are sent", Default: ".*"},
		}},
		"webhook": {Fields: []fieldMeta{
			{Key: "url", Label: "Webhook URL", Description: "HTTP endpoint to POST JSON event data", Required: true},
			{Key: "filter", Label: "Filter", Description: "Regex filter — only matching events are sent", Default: ".*"},
		}},
		"purge": {Fields: []fieldMeta{
			{Key: "schedule", Label: "Schedule", Description: "Cron expression or @every interval", Default: "@daily"},
			{Key: "max_age_days", Label: "Max age (days)", Description: "Delete interactions older than this many days", Default: "30"},
		}},
	}

	defaultFields := []fieldMeta{
		{Key: "server_name", Label: "Server name", Description: "Name used in protocol banners and templates", Default: "BreakfastBot"},
		{Key: "notify_filter", Label: "Notify filter", Description: "Default regex filter for notification matching", Default: "^/l"},
		{Key: "notify_string", Label: "Notify string", Description: "String used in notification matching templates", Default: "l"},
		{Key: "ignore_cidrs", Label: "Ignore CIDRs", Description: "Comma-separated source CIDRs to drop before DB/notification"},
		{Key: "ignore_pattern", Label: "Ignore pattern", Description: "Regex matched against events — matching events are dropped"},
	}

	return fields, defaultFields
}

func (a *adminAuth) handleConfigSchema(w http.ResponseWriter, _ *http.Request) {
	if a.configOps == nil {
		writeErr(w, http.StatusServiceUnavailable, "config management not available")
		return
	}
	fields, defaultFields := buildFieldSchema()
	writeJSON(w, http.StatusOK, configSchemaResponse{
		Handlers:  a.configOps.HandlerNames(),
		Notifiers: a.configOps.NotifierNames(),
		Workers:   a.configOps.WorkerNames(),
		Fields:    fields,
		Defaults:  defaultFields,
	})
}

type configPutRequest struct {
	Defaults  map[string]string   `json:"defaults"`
	Handlers  []map[string]string `json:"handlers"`
	Notifiers []map[string]string `json:"notifiers"`
	Workers   []map[string]string `json:"workers"`
}

func (a *adminAuth) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	if a.configOps == nil {
		writeErr(w, http.StatusServiceUnavailable, "config management not available")
		return
	}
	var req configPutRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxConfigBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}

	cf := &types.ConfigFile{
		Defaults:  req.Defaults,
		Handlers:  req.Handlers,
		Notifiers: req.Notifiers,
		Workers:   req.Workers,
	}

	if errs := a.configOps.Validate(cf); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "validation failed",
			"errors": errs,
		})
		return
	}

	if err := a.configOps.Write(cf); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to write config: "+err.Error())
		return
	}

	reloading := a.app != nil
	writeJSON(w, http.StatusOK, map[string]any{
		"saved":     true,
		"reloading": reloading,
	})

	if reloading {
		go func() {
			time.Sleep(500 * time.Millisecond)
			if err := a.app.Reload(); err != nil {
				lg().Error("config reload after save failed", "err", err)
			}
		}()
	}
}
