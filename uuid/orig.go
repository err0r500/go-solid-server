package uuid

import (
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/err0r500/go-solid-server/uc"
)

type uuidGen struct{}

func New() uc.UUIDGenerator {
	return uuidGen{}
}

func (uuidGen) UUID() string {
	uuid := make([]byte, 16)
	io.ReadFull(rand.Reader, uuid)
	uuid[8] = uuid[8]&^0xc0 | 0x80
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return hex.EncodeToString(uuid)
}
