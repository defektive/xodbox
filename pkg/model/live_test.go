package model

import (
	"testing"
	"time"
)

func TestInteractionHubDeliversToSubscribers(t *testing.T) {
	ch, cancel := SubscribeInteractions()
	defer cancel()

	i := &Interaction{Handler: "tcp", RequestTarget: "/x"}
	PublishInteraction(i)

	select {
	case got := <-ch:
		if got != i {
			t.Errorf("received %+v, want the published interaction", got)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive the published interaction")
	}
}

func TestInteractionHubUnsubscribeStopsDelivery(t *testing.T) {
	ch, cancel := SubscribeInteractions()
	cancel() // unsubscribe immediately; channel is closed

	PublishInteraction(&Interaction{Handler: "dns"})

	// A closed, unsubscribed channel yields the zero value without blocking.
	select {
	case got, ok := <-ch:
		if ok {
			t.Errorf("unsubscribed channel still received %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("read on closed channel should not block")
	}

	// cancel must be idempotent (no panic on double close).
	cancel()
}

func TestInteractionHubIsNonBlockingWhenBufferFull(t *testing.T) {
	ch, cancel := SubscribeInteractions()
	defer cancel()

	// Publish far more than the buffer without a reader; must not block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10_000; i++ {
			PublishInteraction(&Interaction{Handler: "tcp"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PublishInteraction blocked on a full subscriber buffer")
	}
	_ = ch
}
