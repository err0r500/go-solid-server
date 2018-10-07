package sparql_test

import (
	"strings"
	"testing"

	"github.com/err0r500/go-solid-server/sparql"

	"github.com/err0r500/go-solid-server/domain"
	"github.com/stretchr/testify/assert"
)

func TestSPARQLInsertLiteralWithDataType(t *testing.T) {
	graph := domain.NewGraph("https://test/")
	code, err := sparql.New().SPARQLUpdate(graph, strings.NewReader("INSERT DATA { <a> <b> \"123\"^^<http://www.w3.org/2001/XMLSchema#int> . }"))
	assert.Equal(t, 200, code)
	assert.NoError(t, err)
	assert.Equal(t, 1, graph.Len())
}

func TestSPARQLUpdateBnodePresent(t *testing.T) {
	graph := domain.NewGraph("https://test/")
	code, err := sparql.New().SPARQLUpdate(graph, strings.NewReader("INSERT DATA { <a> <b> [ <c> <d> ] . }"))
	assert.Equal(t, 200, code)
	assert.NoError(t, err)
	assert.Equal(t, 2, graph.Len())

	code, err = sparql.New().SPARQLUpdate(graph, strings.NewReader("DELETE DATA { <a> <b> [ <c> <d> ] . }"))
	assert.Equal(t, 500, code)
	assert.Error(t, err)
}

func TestSPARQLUpdateTripleNotPresent(t *testing.T) {
	graph := domain.NewGraph("https://test/")
	code, err := sparql.New().SPARQLUpdate(graph, strings.NewReader("INSERT DATA { <a> <b> <c> . }"))
	assert.Equal(t, 200, code)
	assert.NoError(t, err)
	assert.Equal(t, 1, graph.Len())

	code, err = sparql.New().SPARQLUpdate(graph, strings.NewReader("DELETE DATA { <a> <b> <d> . }"))
	assert.Equal(t, 409, code)
	assert.Error(t, err)
}

func TestSPARQLUpdateMultipleTriples(t *testing.T) {
	graph := domain.NewGraph("https://test/")
	code, err := sparql.New().SPARQLUpdate(graph, strings.NewReader("INSERT DATA { <a> <b> <c> . }; INSERT DATA { <a> <b> <d> . }"))
	assert.Equal(t, 200, code)
	assert.NoError(t, err)
	assert.Equal(t, 2, graph.Len())

	code, err = sparql.New().SPARQLUpdate(graph, strings.NewReader("DELETE DATA { <a> <b> <c> . }; DELETE DATA { <a> <b> <d> . }; INSERT DATA { <a> <b> <f> . }"))
	assert.Equal(t, 200, code)
	assert.NoError(t, err)
	assert.Equal(t, 1, graph.Len())
}
