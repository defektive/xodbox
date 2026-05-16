package ftp

import (
	"testing"

	"github.com/defektive/xodbox/pkg/types"
)

func TestNewHandlerDefaults(t *testing.T) {
	h := NewHandler(map[string]string{"listener": "127.0.0.1:2121"})

	if h.Name() != "FTP" {
		t.Errorf("Name() = %q, want FTP", h.Name())
	}

	concrete := h.(*Handler)
	if concrete.ServerName != "FTP Server" {
		t.Errorf("default ServerName = %q, want %q", concrete.ServerName, "FTP Server")
	}
	wantDirs := []string{"test/old/fake", "test/new/fake"}
	if len(concrete.FakeDirTree) != len(wantDirs) {
		t.Fatalf("FakeDirTree len = %d, want %d", len(concrete.FakeDirTree), len(wantDirs))
	}
	for i, d := range wantDirs {
		if concrete.FakeDirTree[i] != d {
			t.Errorf("FakeDirTree[%d] = %q, want %q", i, concrete.FakeDirTree[i], d)
		}
	}
}

func TestNewHandlerCustomConfig(t *testing.T) {
	h := NewHandler(map[string]string{
		"listener":      "0.0.0.0:21",
		"server_name":   "honeypot-ftp",
		"fake_dir_tree": "a/b,c/d,e",
	}).(*Handler)

	if h.ServerName != "honeypot-ftp" {
		t.Errorf("ServerName = %q, want honeypot-ftp", h.ServerName)
	}
	if h.Listener != "0.0.0.0:21" {
		t.Errorf("Listener = %q, want 0.0.0.0:21", h.Listener)
	}
	if len(h.FakeDirTree) != 3 || h.FakeDirTree[2] != "e" {
		t.Errorf("FakeDirTree = %v, want [a/b c/d e]", h.FakeDirTree)
	}
}

func TestGetAFSCreatesDirs(t *testing.T) {
	dirs := []string{"foo/bar", "baz"}
	fs := getAFS(dirs)

	for _, d := range dirs {
		fi, err := fs.Stat(d)
		if err != nil {
			t.Errorf("stat %q: %v", d, err)
			continue
		}
		if !fi.IsDir() {
			t.Errorf("%q should be a directory", d)
		}
	}
}

func TestDispatchEvent(t *testing.T) {
	h := &Handler{
		name:            "FTP",
		dispatchChannel: make(chan types.InteractionEvent, 1),
	}

	h.DispatchEvent(AuthFail, "5.6.7.8:21")

	select {
	case evt := <-h.dispatchChannel:
		ftpEvt, ok := evt.(*Event)
		if !ok {
			t.Fatalf("got %T, want *Event", evt)
		}
		if ftpEvt.action != AuthFail {
			t.Errorf("action = %v, want AuthFail", ftpEvt.action)
		}
		if ftpEvt.RemoteAddr != "5.6.7.8" {
			t.Errorf("RemoteAddr = %q, want 5.6.7.8", ftpEvt.RemoteAddr)
		}
	default:
		t.Fatal("no event dispatched")
	}
}
