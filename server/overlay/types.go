package overlay

type ControlCommand struct {
	Action string `json:"action"`
	Data   any    `json:"data"`
}

type NetAddr struct {
	Net     string `json:"net"`
	Address string `json:"address"`
	Session string `json:"session,omitempty"`
}
