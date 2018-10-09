package uc_test

import (
	"strings"
	"testing"

	"github.com/err0r500/go-solid-server/constant"
	"github.com/err0r500/go-solid-server/domain"
	"github.com/err0r500/go-solid-server/encoder"
	"github.com/err0r500/go-solid-server/uc"
	"github.com/stretchr/testify/assert"
)

func TestGraphPatch(t *testing.T) {
	var (
		buf   string
		err   error
		graph = domain.NewGraph("https://test/")
	)

	h := encoder.New()

	s := uc.Interactor{}
	s.JSONPatch(graph, strings.NewReader(`{"a":{"b":[{"type":"uri","value":"c"}]}}`))
	buf, err = h.Serialize(graph, constant.TextTurtle)
	assert.Nil(t, err)
	assert.Equal(t, buf, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c> .\n\n")

	s.JSONPatch(graph, strings.NewReader(`{"a":{"b":[{"type":"uri","value":"c2"}]}}`))
	buf, err = h.Serialize(graph, constant.TextTurtle)
	assert.Nil(t, err)
	assert.Equal(t, buf, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c2> .\n\n")

	s.JSONPatch(graph, strings.NewReader(`{"a":{"b2":[{"type":"uri","value":"c2"}]}}`))
	buf, err = h.Serialize(graph, constant.TextTurtle)
	assert.Nil(t, err)
	assert.Equal(t, buf, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c2> ;\n    <b2> <c2> .\n\n")
}
