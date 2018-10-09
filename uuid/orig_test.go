package uuid_test

import (
	"testing"

	"github.com/err0r500/go-solid-server/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewUUID(t *testing.T) {
	assert.Equal(t, 32, len(uuid.New().UUID()))
}
