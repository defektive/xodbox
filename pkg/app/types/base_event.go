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
