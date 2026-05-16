package httpx

import (
	"net/http"
	"testing"

	"github.com/defektive/xodbox/pkg/mdaas"
)

func mkReq(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return r
}

func TestGetOSFromRequestFromQuery(t *testing.T) {
	r := mkReq(t, "http://x/?o=linux")
	got, err := getOSFromRequest(r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != mdaas.TargetOSLinux {
		t.Errorf("got %q, want linux", got)
	}
}

func TestGetOSFromRequestFromPath(t *testing.T) {
	// path has >3 segments → third-from-last is the OS
	r := mkReq(t, "http://x/build/linux/amd64/simple-ssh")
	got, err := getOSFromRequest(r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != mdaas.TargetOSLinux {
		t.Errorf("got %q, want linux", got)
	}
}

func TestGetOSFromRequestUnknown(t *testing.T) {
	r := mkReq(t, "http://x/?o=nope")
	if _, err := getOSFromRequest(r); err == nil {
		t.Error("expected error for unknown OS")
	}
}

func TestGetArchFromQuery(t *testing.T) {
	r := mkReq(t, "http://x/?a=amd64")
	got, err := getArchFromQuery(r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != mdaas.TargetArchAmd64 {
		t.Errorf("got %q, want amd64", got)
	}
}

func TestGetArchFromPath(t *testing.T) {
	r := mkReq(t, "http://x/build/linux/aarch64/simple-ssh")
	got, err := getArchFromQuery(r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != mdaas.TargetArchArm64 {
		t.Errorf("got %q, want arm64 (aarch64 maps to arm64)", got)
	}
}

func TestGetArmFromQuery(t *testing.T) {
	r := mkReq(t, "http://x/?a=armv7l")
	got, err := getArmFromQuery(r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "7" {
		t.Errorf("got %q, want 7", got)
	}
}

func TestGetArmFromQueryUnknown(t *testing.T) {
	r := mkReq(t, "http://x/?a=arm-unrecognised")
	if _, err := getArmFromQuery(r); err == nil {
		t.Error("expected error for unknown arm variant")
	}
}

func TestGetProgramFromQuery(t *testing.T) {
	r := mkReq(t, "http://x/?p=bind-shell")
	got, err := getProgramFromQuery(r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got == "" {
		t.Error("expected program path, got empty")
	}
}

func TestGetProgramFromPath(t *testing.T) {
	r := mkReq(t, "http://x/build/linux/amd64/simple-ssh")
	got, err := getProgramFromQuery(r)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got == "" {
		t.Error("expected program path, got empty")
	}
}
