package xodbox

import (
	"fmt"
	"strings"

	"github.com/defektive/xodbox/pkg/model"
	"github.com/defektive/xodbox/pkg/types"
)

// sinkHitEvent wraps an original InteractionEvent with the matching sink's
// metadata so notifiers can render enriched "sink hit" messages. It
// implements types.InteractionEvent and types.SinkHitProvider.
type sinkHitEvent struct {
	inner types.InteractionEvent
	slug  string
	desc  string
	link  string
}

func newSinkHitEvent(inner types.InteractionEvent, sink model.Sink, publicURL string) *sinkHitEvent {
	var link string
	if publicURL != "" {
		link = strings.TrimRight(publicURL, "/") + "/" + sink.Slug
	}
	return &sinkHitEvent{
		inner: inner,
		slug:  sink.Slug,
		desc:  sink.Description,
		link:  link,
	}
}

func (s *sinkHitEvent) Details() string {
	return fmt.Sprintf("Sink hit: %s — %s", s.slug, s.inner.Details())
}

func (s *sinkHitEvent) RemoteIP() string                       { return s.inner.RemoteIP() }
func (s *sinkHitEvent) RemotePort() int                        { return s.inner.RemotePort() }
func (s *sinkHitEvent) UserAgent() string                      { return s.inner.UserAgent() }
func (s *sinkHitEvent) Data() string                           { return s.inner.Data() }
func (s *sinkHitEvent) Dispatch(_ chan types.InteractionEvent) {}

func (s *sinkHitEvent) FilterString() string {
	return fmt.Sprintf("SINK %s %s", s.slug, s.inner.FilterString())
}

// SinkHitProvider implementation.
func (s *sinkHitEvent) SinkSlug() string        { return s.slug }
func (s *sinkHitEvent) SinkDescription() string { return s.desc }
func (s *sinkHitEvent) SinkLink() string        { return s.link }

// CurlCommand delegates to the wrapped event when it supports curl replay.
func (s *sinkHitEvent) CurlCommand() string {
	if cp, ok := s.inner.(types.CurlProvider); ok {
		return cp.CurlCommand()
	}
	return ""
}
