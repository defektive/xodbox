package httpx

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

func TestLoginEventFilterString(t *testing.T) {
	e := NewLoginEvent("alice", "10.0.0.5", "curl/8")
	if got, want := e.FilterString(), "HTTPX Login alice from 10.0.0.5"; got != want {
		t.Errorf("FilterString = %q, want %q", got, want)
	}
	if i := e.Interaction(); i == nil || i.RequestType != "LOGIN" || i.RequestTarget != "alice" {
		t.Errorf("Interaction = %+v, want LOGIN/alice record", i)
	}
	if !strings.Contains(e.Details(), "alice") {
		t.Errorf("Details = %q, want it to mention the user", e.Details())
	}
}

// notifyTestServer starts an admin surface wired to a dispatch channel, with
// notify_logins set as given, plus a fresh user and cookie-jar client.
func notifyTestServer(t *testing.T, notify bool) (*httptest.Server, *http.Client, *model.User, chan types.InteractionEvent) {
	t.Helper()
	u, err := model.CreateUser(uniqueName("admin"), testPassword, model.RoleAdmin)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	events := make(chan types.InteractionEvent, 1)
	handler, err := (&Handler{NotifyLogins: notify, dispatchChannel: events}).adminHandler("/")
	if err != nil {
		t.Fatalf("adminHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return srv, &http.Client{Jar: jar}, u, events
}

// A successful login dispatches a LoginEvent when notify_logins is enabled.
func TestLoginNotifyDispatch(t *testing.T) {
	srv, c, u, events := notifyTestServer(t, true)
	csrf := getCSRF(t, c, srv.URL)
	resp := postJSON(t, c, srv.URL+"/api/login", csrf, loginRequest{Username: u.Username, Password: testPassword})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d, want 200", resp.StatusCode)
	}

	select {
	case e := <-events:
		if _, ok := e.(*LoginEvent); !ok {
			t.Fatalf("dispatched %T, want *LoginEvent", e)
		}
		if !strings.Contains(e.FilterString(), "HTTPX Login "+u.Username) {
			t.Errorf("FilterString = %q", e.FilterString())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no login event dispatched")
	}
}

// With notify_logins disabled, a login dispatches nothing.
func TestLoginNotifyDisabled(t *testing.T) {
	srv, c, u, events := notifyTestServer(t, false)
	csrf := getCSRF(t, c, srv.URL)
	resp := postJSON(t, c, srv.URL+"/api/login", csrf, loginRequest{Username: u.Username, Password: testPassword})
	resp.Body.Close()

	select {
	case e := <-events:
		t.Fatalf("unexpected event dispatched: %T", e)
	case <-time.After(200 * time.Millisecond):
		// expected: nothing
	}
}
