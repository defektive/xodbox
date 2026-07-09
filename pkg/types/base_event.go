package types

type BaseEvent struct {
	RemoteAddr       string
	RemotePortNumber int
	UserAgentString  string
	RawData          []byte
}

func (e *BaseEvent) Details() string {
	return "Default Event"
}

func (e *BaseEvent) RemoteIP() string {
	return e.RemoteAddr
}

func (e *BaseEvent) RemotePort() int {
	return e.RemotePortNumber
}

func (e *BaseEvent) UserAgent() string {
	return e.UserAgentString
}

func (e *BaseEvent) Data() string {
	return string(e.RawData)
}

// FilterString is the fallback match target for events that don't override
// it. Concrete handler events replace this with a canonical
// "HANDLER ACTION DETAIL from IP" string; the base default just exposes the
// raw data and source IP so a bare event is still filterable.
func (e *BaseEvent) FilterString() string {
	if e.RemoteAddr == "" {
		return e.Data()
	}
	return e.Data() + " from " + e.RemoteAddr
}

func (e *BaseEvent) Dispatch(cc chan InteractionEvent) {
	go func() {
		cc <- e
	}()
}
