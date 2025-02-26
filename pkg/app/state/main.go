package state

type appState struct {
	Version string `json:"version"`
}

var AppState appState
