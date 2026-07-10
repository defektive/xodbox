package model

import "sync"

// interactionHub is a tiny in-process fan-out for newly persisted interactions.
// The app event loop publishes each stored interaction; the admin API's event
// stream (SSE) subscribes to push them to connected browsers in real time.
type interactionHub struct {
	mu   sync.Mutex
	subs map[chan *Interaction]struct{}
}

var hub = &interactionHub{subs: make(map[chan *Interaction]struct{})}

// PublishInteraction fans out i to every current subscriber. Sends are
// non-blocking: a subscriber whose buffer is full misses the event rather than
// stalling the event loop (the client can reload to catch up). It is a cheap
// no-op when nobody is subscribed.
func PublishInteraction(i *Interaction) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	for ch := range hub.subs {
		select {
		case ch <- i:
		default:
		}
	}
}

// SubscribeInteractions registers a subscriber and returns its channel plus an
// unsubscribe function. The caller must call unsubscribe when done; it removes
// and closes the channel.
func SubscribeInteractions() (<-chan *Interaction, func()) {
	ch := make(chan *Interaction, 64)
	hub.mu.Lock()
	hub.subs[ch] = struct{}{}
	hub.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			hub.mu.Lock()
			delete(hub.subs, ch)
			close(ch)
			hub.mu.Unlock()
		})
	}
	return ch, cancel
}
