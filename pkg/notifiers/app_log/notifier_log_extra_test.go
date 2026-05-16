package app_log

import (
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

func TestNewNotifierDefaultFilter(t *testing.T) {
	n := NewNotifier(map[string]string{}).(*Notifier)
	if !n.Filter().MatchString("anything") {
		t.Error("default filter should match everything")
	}
	if n.Name() != "app_log" {
		t.Errorf("Name() = %q, want app_log", n.Name())
	}
}

func TestNewNotifierCustomFilter(t *testing.T) {
	n := NewNotifier(map[string]string{"filter": "^/admin"}).(*Notifier)
	if n.Filter().MatchString("/user") {
		t.Error("custom filter should not match /user")
	}
	if !n.Filter().MatchString("/admin/panel") {
		t.Error("custom filter should match /admin/panel")
	}
}

func TestSendReturnsNil(t *testing.T) {
	n := NewNotifier(map[string]string{}).(*Notifier)
	if err := n.Send(&types.BaseEvent{}); err != nil {
		t.Errorf("Send returned %v, want nil", err)
	}
}
