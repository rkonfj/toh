package api

type BytesUsage struct {
	In  uint64 `json:"in"`
	Out uint64 `json:"out"`
}

type Limit struct {
	Bytes     string   `json:"bytes,omitempty"`
	InBytes   string   `json:"inBytes,omitempty"`
	OutBytes  string   `json:"outBytes,omitempty"`
	Whitelist []string `json:"whitelist,omitempty"`
	Blacklist []string `json:"blacklist,omitempty"`
}

type Key struct {
	Name       string      `json:"name,omitempty"`
	Key        string      `json:"key"`
	Limit      *Limit      `json:"limit,omitempty"`
	BytesUsage *BytesUsage `json:"bytesUsage,omitempty"`
}
