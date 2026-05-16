package model

import (
	"path/filepath"
	"regexp"
	"testing"
)

func TestDBOptionsDBPathDefault(t *testing.T) {
	opts := DBOptions{}
	if got := opts.DBPath(); got != defaultDBPath {
		t.Errorf("DBPath() = %q, want %q", got, defaultDBPath)
	}
}

func TestDBOptionsDBPathOverride(t *testing.T) {
	opts := DBOptions{Path: "/tmp/custom.db"}
	if got := opts.DBPath(); got != "/tmp/custom.db" {
		t.Errorf("DBPath() = %q, want %q", got, "/tmp/custom.db")
	}
}

func TestDBOptionsShouldReset(t *testing.T) {
	zero := DBOptions{}
	if zero.ShouldReset() {
		t.Error("zero-value Reset should be false")
	}
	withReset := DBOptions{Reset: true}
	if !withReset.ShouldReset() {
		t.Error("Reset=true should be reported")
	}
}

func TestPayloadPatternRegexpMemoised(t *testing.T) {
	p := &Payload{Pattern: "^foo[0-9]+$"}

	first := p.PatternRegexp()
	if first == nil {
		t.Fatal("PatternRegexp returned nil")
	}
	if !first.MatchString("foo123") {
		t.Error("compiled regexp should match 'foo123'")
	}
	if first.MatchString("bar") {
		t.Error("compiled regexp should not match 'bar'")
	}

	second := p.PatternRegexp()
	if first != second {
		t.Error("PatternRegexp should cache the compiled regexp")
	}
}

func TestPayloadPatternRegexpType(t *testing.T) {
	p := &Payload{Pattern: ".*"}
	if _, ok := interface{}(p.PatternRegexp()).(*regexp.Regexp); !ok {
		t.Errorf("PatternRegexp should return *regexp.Regexp")
	}
}

// resetDB clears the package-level singleton and points the next
// LoadDBWithOptions call at a fresh sqlite file inside the test's temp
// directory. Tests that hit the database must call this first.
func resetDB(t *testing.T) {
	t.Helper()
	db = nil
	LoadDBWithOptions(DBOptions{Path: filepath.Join(t.TempDir(), "test.db")})
	t.Cleanup(func() { db = nil })
}

func TestLoadDBWithOptionsSeedsDefaultProject(t *testing.T) {
	resetDB(t)

	dp := DefaultProject()
	if dp == nil {
		t.Fatal("DefaultProject() returned nil after seed")
	}
	if dp.Name != "default" {
		t.Errorf("default project Name = %q, want %q", dp.Name, "default")
	}
	if !dp.Default {
		t.Error("default project should have Default=true")
	}
	if dp.ID == 0 {
		t.Error("default project should have been persisted (ID > 0)")
	}
}

func TestDBLazyInit(t *testing.T) {
	resetDB(t)

	got := DB()
	if got == nil {
		t.Fatal("DB() returned nil")
	}
	if got != db {
		t.Error("DB() should return the package-level handle")
	}
}

func TestSortedPayloads(t *testing.T) {
	resetDB(t)

	payloads := []Payload{
		{Name: "second", Pattern: "b", SortOrder: 2},
		{Name: "first", Pattern: "a", SortOrder: 1},
		{Name: "third", Pattern: "c", SortOrder: 3},
	}
	for i := range payloads {
		if err := DB().Create(&payloads[i]).Error; err != nil {
			t.Fatalf("seed payload: %v", err)
		}
	}

	got := SortedPayloads()
	if len(got) != 3 {
		t.Fatalf("len(SortedPayloads()) = %d, want 3", len(got))
	}
	wantOrder := []string{"first", "second", "third"}
	for i, name := range wantOrder {
		if got[i].Name != name {
			t.Errorf("got[%d].Name = %q, want %q", i, got[i].Name, name)
		}
	}
}

func TestSortedInteractionsLimit(t *testing.T) {
	resetDB(t)

	for i := 0; i < 5; i++ {
		ix := Interaction{RemoteAddr: "1.1.1.1", Handler: "test"}
		if err := DB().Create(&ix).Error; err != nil {
			t.Fatalf("seed interaction: %v", err)
		}
	}

	got := SortedInteractions(3)
	if len(got) != 3 {
		t.Errorf("SortedInteractions(3) len = %d, want 3", len(got))
	}
}

func TestBotsAndIsBot(t *testing.T) {
	resetDB(t)

	const bot = "9.9.9.9"
	const human = "8.8.8.8"

	// 31 hits from bot — over the >30 threshold in getBotQuery.
	for i := 0; i < 31; i++ {
		if err := DB().Create(&Interaction{RemoteAddr: bot, Handler: "h"}).Error; err != nil {
			t.Fatalf("seed bot interaction: %v", err)
		}
	}
	// Single hit from a non-bot.
	if err := DB().Create(&Interaction{RemoteAddr: human, Handler: "h"}).Error; err != nil {
		t.Fatalf("seed human interaction: %v", err)
	}

	if !IsBot(bot) {
		t.Errorf("IsBot(%q) = false, want true", bot)
	}
	if IsBot(human) {
		t.Errorf("IsBot(%q) = true, want false", human)
	}

	bots := Bots()
	if len(bots) == 0 {
		t.Fatal("Bots() returned empty result")
	}
	var found bool
	for _, b := range bots {
		if b.RemoteAddr == bot {
			found = true
			if b.Total < 31 {
				t.Errorf("bot total = %d, want >= 31", b.Total)
			}
		}
	}
	if !found {
		t.Errorf("expected %q in Bots() results, got %+v", bot, bots)
	}
}
