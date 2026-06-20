package httpx

import (
	"testing"

	"github.com/defektive/xodbox/pkg/model"
)

// countHTTPXPayloads returns the number of rows in the payloads table for the
// HTTPX type.
func countHTTPXPayloads(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := model.DB().Table("payloads").Where("type = ?", PayloadName).Count(&n).Error; err != nil {
		t.Fatalf("count payloads: %v", err)
	}
	return n
}

// Seed runs CreatePayloadsFromFS only the first time; the module-level
// `seeded` flag must guard subsequent invocations so the embedded payloads
// are not inserted twice.
func TestSeedIsIdempotent(t *testing.T) {
	// Save/restore the global seeded flag so we don't disturb other tests.
	prevSeeded := seeded
	t.Cleanup(func() { seeded = prevSeeded })

	if err := model.DB().Exec("DELETE FROM payloads").Error; err != nil {
		t.Fatalf("clear payloads: %v", err)
	}

	seeded = false
	Seed(model.DB())
	afterFirst := countHTTPXPayloads(t)
	if afterFirst == 0 {
		t.Fatal("first Seed should have inserted embedded payloads")
	}

	// Second call must be a no-op because `seeded` is now true.
	Seed(model.DB())
	afterSecond := countHTTPXPayloads(t)
	if afterSecond != afterFirst {
		t.Errorf("second Seed inserted more rows: before=%d after=%d", afterFirst, afterSecond)
	}
}

// Handler.Seed implements the types.Seeder interface and delegates to the
// package-level Seed against the live DB; it must return nil.
func TestHandlerSeedReturnsNil(t *testing.T) {
	prevSeeded := seeded
	t.Cleanup(func() { seeded = prevSeeded })
	// Mark already seeded so this is a cheap no-op against the DB.
	seeded = true

	h := NewHandler(map[string]string{"listener": "127.0.0.1:0"}).(*Handler)
	if err := h.Seed(); err != nil {
		t.Errorf("Handler.Seed() = %v, want nil", err)
	}
}

// CreatePayloadsFromFS on the embedded FS should yield well-formed payloads;
// re-running against a cleared table reinserts them (it has no internal
// dedupe — the `seeded` flag in Seed provides idempotency, not this function).
func TestCreatePayloadsFromFSEmbedded(t *testing.T) {
	payloads = nil
	t.Cleanup(func() { payloads = nil })
	if err := model.DB().Exec("DELETE FROM payloads").Error; err != nil {
		t.Fatalf("clear payloads: %v", err)
	}

	CreatePayloadsFromFS(&embeddedSeedFS, model.DB())

	if n := countHTTPXPayloads(t); n == 0 {
		t.Fatal("CreatePayloadsFromFS should have inserted embedded payloads")
	}
}
