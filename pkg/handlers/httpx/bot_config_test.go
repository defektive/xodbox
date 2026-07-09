package httpx

import "testing"

func TestBotExemptPrivateConfig(t *testing.T) {
	// Default: exemption on.
	h := NewHandler(map[string]string{"listener": ":0"}).(*Handler)
	if !h.BotExemptPrivate {
		t.Error("bot_exempt_private should default to true")
	}

	// Explicit "false" disables it.
	off := NewHandler(map[string]string{"listener": ":0", "bot_exempt_private": "false"}).(*Handler)
	if off.BotExemptPrivate {
		t.Error(`bot_exempt_private: "false" should disable exemption`)
	}

	// Any other value keeps the default (on).
	on := NewHandler(map[string]string{"listener": ":0", "bot_exempt_private": "true"}).(*Handler)
	if !on.BotExemptPrivate {
		t.Error(`bot_exempt_private: "true" should enable exemption`)
	}
}
