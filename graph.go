package gold

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"

	"github.com/err0r500/go-solid-server/domain"
	crdf "github.com/presbrey/goraptor"
)

// AnyGraph defines methods common to Graph types
type AnyGraph interface {
	Len() int
	URI() string
	//Parse(io.Reader, string)
	//Serialize(string) (string, error)

	//JSONPatch(io.Reader) error
	SPARQLUpdate(*SPARQLUpdate) (int, error)
	IterTriples() chan *domain.Triple

	//ReadFile(string)
	//WriteFile(*os.File, string) error
}

var (
	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
)

// Graph structure
type Graph struct {
	triples map[*domain.Triple]bool

	uri  string
	term domain.Term
}

// NewGraph creates a Graph object
func NewGraph(uri string) *Graph {
	if uri[:5] != "http:" && uri[:6] != "https:" {
		panic(uri)
	}
	return &Graph{
		triples: make(map[*domain.Triple]bool),

		uri:  uri,
		term: domain.NewResource(uri),
	}
}

// Len returns the length of the graph as number of triples in the graph
func (g *Graph) Len() int {
	return len(g.triples)
}

// Term returns a Graph Term object
func (g *Graph) Term() domain.Term {
	return g.term
}

// URI returns a Graph URI object
func (g *Graph) URI() string {
	return g.uri
}

func term2term(term crdf.Term) domain.Term {
	switch term := term.(type) {
	case *crdf.Blank:
		return domain.NewBlankNode(term.String())
	case *crdf.Literal:
		if len(term.Datatype) > 0 {
			return domain.NewLiteralWithLanguageAndDatatype(term.Value, term.Lang, domain.NewResource(term.Datatype))
		}
		return domain.NewLiteral(term.Value)
	case *crdf.Uri:
		return domain.NewResource(term.String())
	}
	return nil
}

func isNilOrEquals(t1 domain.Term, t2 domain.Term) bool {
	if t1 == nil {
		return true
	}
	return t2.Equal(t1)
}

// One returns one triple based on a triple pattern of S, P, O objects
func (g *Graph) One(s domain.Term, p domain.Term, o domain.Term) *domain.Triple {
	for triple := range g.IterTriples() {
		if isNilOrEquals(s, triple.Subject) && isNilOrEquals(p, triple.Predicate) && isNilOrEquals(o, triple.Object) {
			return triple
		}
	}
	return nil
}

// IterTriples iterates through all the triples in a graph
func (g *Graph) IterTriples() (ch chan *domain.Triple) {
	ch = make(chan *domain.Triple)
	go func() {
		for triple := range g.triples {
			ch <- triple
		}
		close(ch)
	}()
	return ch
}

// Add is used to add a Triple object to the graph
func (g *Graph) Add(t *domain.Triple) {
	g.triples[t] = true
}

// AddTriple is used to add a triple made of individual S, P, O objects
func (g *Graph) AddTriple(s domain.Term, p domain.Term, o domain.Term) {
	g.triples[domain.NewTriple(s, p, o)] = true
}

// Remove is used to remove a Triple object
func (g *Graph) Remove(t *domain.Triple) {
	delete(g.triples, t)
}

// All is used to return all triples that match a given pattern of S, P, O objects
func (g *Graph) All(s domain.Term, p domain.Term, o domain.Term) []*domain.Triple {
	var triples []*domain.Triple
	for triple := range g.IterTriples() {
		if s == nil && p == nil && o == nil {
			continue
		}
		if isNilOrEquals(s, triple.Subject) && isNilOrEquals(p, triple.Predicate) && isNilOrEquals(o, triple.Object) {
			triples = append(triples, triple)
		}
	}
	return triples
}

// AddStatement adds a Statement object
func (g *Graph) AddStatement(st *crdf.Statement) {
	g.AddTriple(term2term(st.Subject), term2term(st.Predicate), term2term(st.Object))
}

// ParseBase is used to parse RDF data from a reader, using the provided mime type and a base URI
func (g *Graph) ParseBase(reader io.Reader, mime string, baseURI string) {
	if len(baseURI) < 1 {
		baseURI = g.uri
	}
	parserName := mimeParser[mime]
	if len(parserName) == 0 {
		parserName = "guess"
	}
	parser := crdf.NewParser(parserName)
	defer parser.Free()
	out := parser.Parse(reader, baseURI)
	for s := range out {
		g.AddStatement(s)
	}
}

type JSONLDHandler struct{}

func (JSONLDHandler) Serialize(g *Graph, mime string) (string, error) { // fixme : mime is not used, just to implement the Serializer interface, check if rdf really needs it
	r := []map[string]interface{}{}
	for elt := range g.IterTriples() {
		one := map[string]interface{}{
			"@id": elt.Subject.(*domain.Resource).URI,
		}
		switch t := elt.Object.(type) {
		case *domain.Resource:
			one[elt.Predicate.(*domain.Resource).URI] = []map[string]string{
				{
					"@id": t.URI,
				},
			}
			break
		case *domain.Literal:
			v := map[string]string{
				"@value": t.Value,
			}
			if t.Datatype != nil && len(t.Datatype.String()) > 0 {
				v["@type"] = t.Datatype.String()
			}
			if len(t.Language) > 0 {
				v["@language"] = t.Language
			}
			one[elt.Predicate.(*domain.Resource).URI] = []map[string]string{v}
		}
		r = append(r, one)
	}
	bytes, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
