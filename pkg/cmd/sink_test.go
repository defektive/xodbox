package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

var cliSinkSeq atomic.Int64

func TestSinkAddGeneratesSlugOnStdout(t *testing.T) {
	var out, errBuf bytes.Buffer
	sinkAddCmd.SetOut(&out)
	sinkAddCmd.SetErr(&errBuf)
	t.Cleanup(func() { sinkAddCmd.SetOut(nil); sinkAddCmd.SetErr(nil) })

	sinkDescription = "generated for test"
	t.Cleanup(func() { sinkDescription = "" })

	if err := sinkAddCmd.RunE(sinkAddCmd, []string{}); err != nil {
		t.Fatalf("sink add: %v", err)
	}
	slug := strings.TrimSpace(out.String())
	if !model.ValidSlug(slug) {
		t.Errorf("stdout slug %q is not valid", slug)
	}
	// The confirmation must go to stderr, keeping stdout clean for scripts.
	if strings.Contains(out.String(), "created sink") {
		t.Error("confirmation leaked to stdout")
	}
	if !strings.Contains(errBuf.String(), "created sink") {
		t.Error("confirmation missing from stderr")
	}
}

func TestSinkAddAndRemove(t *testing.T) {
	slug := fmt.Sprintf("cli-sink-%d", cliSinkSeq.Add(1))

	if err := sinkAddCmd.RunE(sinkAddCmd, []string{slug}); err != nil {
		t.Fatalf("sink add: %v", err)
	}
	if _, err := model.SinkBySlug(slug); err != nil {
		t.Fatalf("sink not created: %v", err)
	}

	if err := sinkRmCmd.RunE(sinkRmCmd, []string{slug}); err != nil {
		t.Fatalf("sink rm: %v", err)
	}
	if _, err := model.SinkBySlug(slug); err == nil {
		t.Error("sink should be removed")
	}
}
