package gold

import (
	"strings"
	"testing"

	"github.com/err0r500/go-solid-server/domain"
	jsonld "github.com/linkeddata/gojsonld"
	"github.com/stretchr/testify/assert"
)

func TestJSONTerm2Term(t *testing.T) {
	term := jsonld.NewResource("http://test.org/")
	res1 := jterm2term(term)
	res2 := domain.NewResource("http://test.org/")
	assert.True(t, res2.Equal(res1))

	term = jsonld.NewLiteralWithDatatype("text", jsonld.NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))
	res1 = jterm2term(term)
	res2 = domain.NewLiteralWithDatatype("text", domain.NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))
	assert.True(t, res2.Equal(res1))
}

func TestParseJSONLD(t *testing.T) {
	r := strings.NewReader(`{ "@id": "http://greggkellogg.net/foaf#me", "http://xmlns.com/foaf/0.1/name": "Gregg Kellogg" }`)
	g := NewGraph("https://test.org/")
	OrigParser{}.Parse(g, r, "application/ld+json")
	assert.Equal(t, 1, g.Len())
}

func TestSerializeJSONLD(t *testing.T) {
	g := NewGraph("https://test.org/")
	g.AddTriple(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("c"))
	assert.Equal(t, 1, g.Len())
	h := RdfHandler{jsonldSerializer: JSONLDHandler{}}
	toJSON, _ := h.jsonldSerializer.Serialize(g, "application/ld+json")
	assert.Equal(t, `[{"@id":"a","b":[{"@id":"c"}]}]`, toJSON)
}

func TestGraphPatch(t *testing.T) {
	var (
		buf   string
		err   error
		graph = NewGraph("https://test/")
	)
	h := RdfHandler{jsonldSerializer: JSONLDHandler{}, rdfSerializer: RdfHandler{}}

	s := Server{}
	s.JSONPatch(graph, strings.NewReader(`{"a":{"b":[{"type":"uri","value":"c"}]}}`))
	buf, err = h.rdfSerializer.Serialize(graph, "text/turtle")
	assert.Nil(t, err)
	assert.Equal(t, buf, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c> .\n\n")

	s.JSONPatch(graph, strings.NewReader(`{"a":{"b":[{"type":"uri","value":"c2"}]}}`))
	buf, err = h.rdfSerializer.Serialize(graph, "text/turtle")
	assert.Nil(t, err)
	assert.Equal(t, buf, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c2> .\n\n")

	s.JSONPatch(graph, strings.NewReader(`{"a":{"b2":[{"type":"uri","value":"c2"}]}}`))
	buf, err = h.rdfSerializer.Serialize(graph, "text/turtle")
	assert.Nil(t, err)
	assert.Equal(t, buf, "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\n<a>\n    <b> <c2> ;\n    <b2> <c2> .\n\n")
}

func TestGraphOne(t *testing.T) {
	g := NewGraph("http://test/")

	g.AddTriple(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("c"))
	assert.Equal(t, g.One(domain.NewResource("a"), nil, nil).String(), "<a> <b> <c> .")
	assert.Equal(t, g.One(domain.NewResource("a"), domain.NewResource("b"), nil).String(), "<a> <b> <c> .")

	g.AddTriple(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("d"))
	assert.Equal(t, g.One(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("d")).String(), "<a> <b> <d> .")
	assert.Equal(t, g.One(nil, domain.NewResource("b"), domain.NewResource("d")).String(), "<a> <b> <d> .")

	g.AddTriple(domain.NewResource("g"), domain.NewResource("b2"), domain.NewLiteral("e"))
	assert.Equal(t, g.One(nil, domain.NewResource("b2"), nil).String(), "<g> <b2> \"e\" .")
	assert.Equal(t, g.One(nil, nil, domain.NewLiteral("e")).String(), "<g> <b2> \"e\" .")

	assert.Nil(t, g.One(domain.NewResource("x"), nil, nil))
	assert.Nil(t, g.One(nil, domain.NewResource("x"), nil))
	assert.Nil(t, g.One(nil, nil, domain.NewResource("x")))
}

func TestGraphAll(t *testing.T) {
	g := NewGraph("http://test/")
	g.AddTriple(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("c"))
	g.AddTriple(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("d"))
	g.AddTriple(domain.NewResource("a"), domain.NewResource("f"), domain.NewLiteral("h"))
	g.AddTriple(domain.NewResource("g"), domain.NewResource("b2"), domain.NewResource("e"))
	g.AddTriple(domain.NewResource("g"), domain.NewResource("b2"), domain.NewResource("c"))

	assert.Equal(t, len(g.All(nil, nil, nil)), 0)
	assert.Equal(t, len(g.All(domain.NewResource("a"), nil, nil)), 3)
	assert.Equal(t, len(g.All(nil, domain.NewResource("b"), nil)), 2)
	assert.Equal(t, len(g.All(nil, nil, domain.NewResource("d"))), 1)
	assert.Equal(t, len(g.All(nil, nil, domain.NewResource("c"))), 2)
}
