package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRDFBrack(t *testing.T) {
	h := URIHandler{}
	assert.Equal(t, "<test>", h.Brack("test"))
	assert.Equal(t, "<test", h.Brack("<test"))
	assert.Equal(t, "test>", h.Brack("test>"))
}

func TestRDFDebrack(t *testing.T) {
	h := URIHandler{}
	assert.Equal(t, "a", h.Debrack("a"))
	assert.Equal(t, "test", h.Debrack("<test>"))
	assert.Equal(t, "<test", h.Debrack("<test"))
	assert.Equal(t, "test>", h.Debrack("test>"))
}

func TestDefrag(t *testing.T) {
	h := URIHandler{}
	assert.Equal(t, "test", h.Defrag("test"))
	assert.Equal(t, "test", h.Defrag("test#me"))
}
