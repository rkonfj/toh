package api

type Stats struct {
	BytesLimit    string      `json:"bytesLimit,omitempty"`
	InBytesLimit  string      `json:"inBytesLimit,omitempty"`
	OutBytesLimit string      `json:"outBytesLimit,omitempty"`
	BytesUsage    *BytesUsage `json:"bytesUsage,omitempty"`
	Status        string      `json:"status"`
}

type BytesUsage struct {
	In  uint64 `json:"in"`
	Out uint64 `json:"out"`
}
