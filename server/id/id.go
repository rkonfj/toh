package id

import (
	"crypto/rand"

	"github.com/decred/base58"
)

func Generate(length int) string {
	buf := make([]byte, max(length, 8))
	rand.Reader.Read(buf)
	return base58.CheckEncode(buf, [2]byte{1, 0})
}
