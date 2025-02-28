package types

const SourceExternal = "external"
const SourceApplication = "application"

type BaseEvent struct {
	source           string
	details          string
	RemoteAddr       string
	RemotePortNumber int
	UserAgentString  string
	RawData          []byte
}

func (e *BaseEvent) Details() string {
	return e.details
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

func (e *BaseEvent) Dispatch(cc chan InteractionEvent) {
	go func() {
		cc <- e
	}()
}

func (e *BaseEvent) IsApp() bool {
	return e.source == SourceApplication
}

func NewEvent(remoteAddr string, remotePortNumber int, userAgentString string, rawData []byte) *BaseEvent {
	return &BaseEvent{
		source:           SourceExternal,
		details:          "Base Event",
		RemoteAddr:       remoteAddr,
		RemotePortNumber: remotePortNumber,
		UserAgentString:  userAgentString,
		RawData:          rawData,
	}
}

func NewInternalEvent(rawData []byte) *BaseEvent {
	return &BaseEvent{source: SourceApplication, details: "Internal Event", RawData: rawData}
}
