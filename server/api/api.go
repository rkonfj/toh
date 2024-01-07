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

type Stats struct {
	BytesLimit    string              `json:"bytesLimit,omitempty"`
	InBytesLimit  string              `json:"inBytesLimit,omitempty"`
	OutBytesLimit string              `json:"outBytesLimit,omitempty"`
	BytesUsage    *BytesUsage         `json:"bytesUsage,omitempty"`
	Status        string              `json:"status"`
	Overlay       map[string][]string `json:"overlay"`
}
