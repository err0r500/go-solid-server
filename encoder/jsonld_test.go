package encoder_test

import (
	"strings"
	"testing"

	"github.com/err0r500/go-solid-server/encoder"

	"github.com/err0r500/go-solid-server/domain"
	jsonld "github.com/linkeddata/gojsonld"
	"github.com/stretchr/testify/assert"
)

func TestJSONTerm2Term(t *testing.T) {
	h := encoder.JSONLDEncoder{}
	term := jsonld.NewResource("http://test.org/")
	res1 := h.ToDomain(term)
	res2 := domain.NewResource("http://test.org/")
	assert.True(t, res2.Equal(res1))

	term = jsonld.NewLiteralWithDatatype("text", jsonld.NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))
	res1 = h.ToDomain(term)
	res2 = domain.NewLiteralWithDatatype("text", domain.NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))
	assert.True(t, res2.Equal(res1))
}

func TestParseJSONLD(t *testing.T) {
	r := strings.NewReader(`{ "@id": "http://greggkellogg.net/foaf#me", "http://xmlns.com/foaf/0.1/name": "Gregg Kellogg" }`)
	g := domain.NewGraph("https://test.org/")
	encoder.New().Parse(g, r, "application/ld+json")
	assert.Equal(t, 1, g.Len())
}

func TestSerializeJSONLD(t *testing.T) {
	g := domain.NewGraph("https://test.org/")
	g.AddTriple(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("c"))
	assert.Equal(t, 1, g.Len())
	h := encoder.New()
	toJSON, _ := h.Serialize(g, "application/ld+json")
	assert.Equal(t, `[{"@id":"a","b":[{"@id":"c"}]}]`, toJSON)
}
