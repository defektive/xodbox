package model

import (
	"errors"
	"testing"
)

func seedInteraction(t *testing.T, ix Interaction) {
	t.Helper()
	if err := DB().Create(&ix).Error; err != nil {
		t.Fatalf("seed interaction: %v", err)
	}
}

func TestPurgeInteractionsRequiresConstraint(t *testing.T) {
	if _, err := MatchingInteractions(InteractionPurgeFilter{}); !errors.Is(err, ErrNoPurgeConstraint) {
		t.Errorf("empty filter error = %v, want ErrNoPurgeConstraint", err)
	}
	if _, err := PurgeInteractions(InteractionPurgeFilter{}); !errors.Is(err, ErrNoPurgeConstraint) {
		t.Errorf("empty filter purge error = %v, want ErrNoPurgeConstraint", err)
	}
}

func TestPurgeInteractionsByCIDR(t *testing.T) {
	// Unique target keeps this test's rows isolated from the shared package DB.
	const target = "/purge-cidr-test"
	seedInteraction(t, Interaction{Handler: "httpx", RemoteAddr: "198.51.100.5", RequestTarget: target})
	seedInteraction(t, Interaction{Handler: "httpx", RemoteAddr: "198.51.100.6", RequestTarget: target})
	seedInteraction(t, Interaction{Handler: "httpx", RemoteAddr: "8.8.8.8", RequestTarget: target})

	f := InteractionPurgeFilter{Remotes: []string{"198.51.100.0/24"}, Target: target}

	matched, err := MatchingInteractions(f)
	if err != nil {
		t.Fatalf("MatchingInteractions: %v", err)
	}
	if len(matched) != 2 {
		t.Fatalf("matched %d rows, want 2", len(matched))
	}

	n, err := PurgeInteractions(f)
	if err != nil {
		t.Fatalf("PurgeInteractions: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d rows, want 2", n)
	}

	// The 8.8.8.8 row must survive.
	var remaining int64
	DB().Model(&Interaction{}).Where("request_target = ?", target).Count(&remaining)
	if remaining != 1 {
		t.Errorf("remaining rows = %d, want 1 (the non-matching source)", remaining)
	}
}

func TestPurgeInteractionsByTargetAndHandler(t *testing.T) {
	const target = "/purge-target-test-beacon"
	seedInteraction(t, Interaction{Handler: "httpx", RemoteAddr: "192.0.2.10", RequestTarget: target})
	seedInteraction(t, Interaction{Handler: "dns", RemoteAddr: "192.0.2.11", RequestTarget: target})

	// Handler filter should scope the delete to httpx only.
	n, err := PurgeInteractions(InteractionPurgeFilter{Target: "purge-target-test-beacon", Handler: "httpx"})
	if err != nil {
		t.Fatalf("PurgeInteractions: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d rows, want 1", n)
	}

	var remaining int64
	DB().Model(&Interaction{}).Where("request_target = ?", target).Count(&remaining)
	if remaining != 1 {
		t.Errorf("remaining rows = %d, want 1 (the dns row)", remaining)
	}
}

func TestPurgeInteractionsInvalidCIDR(t *testing.T) {
	if _, err := PurgeInteractions(InteractionPurgeFilter{Remotes: []string{"nonsense"}}); err == nil {
		t.Error("invalid CIDR should return an error")
	}
}
