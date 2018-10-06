package gold

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"strings"
	"text/scanner"

	"github.com/err0r500/go-solid-server/constant"
	"github.com/err0r500/go-solid-server/encoder"

	"github.com/err0r500/go-solid-server/domain"
	"github.com/err0r500/go-solid-server/uc"
)

// SPARQLUpdateQuery contains a verb, the body of the query and the graph
type SPARQLUpdateQuery struct {
	verb string
	body string

	graph domain.Graph
}

// SPARQLUpdate contains the base URI and a list of queries
type SPARQLUpdate struct {
	baseURI string
	queries []SPARQLUpdateQuery
	parser  uc.Encoder
}

// NewSPARQLUpdate creates a new SPARQL object
func NewSPARQLUpdate(baseURI string) *SPARQLUpdate {
	return &SPARQLUpdate{
		baseURI: baseURI,
		queries: []SPARQLUpdateQuery{},
		parser:  encoder.New(),
	}
}

// Parse parses a SPARQL query from the reader
func (sparql *SPARQLUpdate) Parse(src io.Reader) error {
	b, _ := ioutil.ReadAll(src)
	s := new(scanner.Scanner).Init(bytes.NewReader(b))
	s.Mode = scanner.ScanIdents | scanner.ScanStrings

	start := 0
	level := 0
	verb := ""
	tok := s.Scan()
	for tok != scanner.EOF {
		switch tok {
		case -2:
			if level == 0 {
				if len(verb) > 0 {
					verb += " "
				}
				verb += s.TokenText()
			}

		case 123: // {
			if level == 0 {
				start = s.Position.Offset
			}
			level++

		case 125: // }
			level--
			if level == 0 {
				query := SPARQLUpdateQuery{
					body:  string(b[start+1 : s.Position.Offset]),
					graph: *domain.NewGraph(sparql.baseURI),
					verb:  verb,
				}
				sparql.parser.Parse(&query.graph, strings.NewReader(query.body), constant.TextTurtle)
				sparql.queries = append(sparql.queries, query)
			}

		case 59: // ;
			if level == 0 {
				verb = ""
			}
		}

		tok = s.Scan()
	}

	return nil
}

// SPARQLUpdate is used to update a graph from a SPARQL query
// Ugly, needs to be improved
func (sparql *SPARQLUpdate) SPARQLUpdate(g *domain.Graph) (int, error) {
	for _, query := range sparql.queries {
		if query.verb == "DELETE" || query.verb == "DELETE DATA" {
			for pattern := range query.graph.IterTriples() {
				found := false
				for _, triple := range g.All(pattern.Subject, pattern.Predicate, nil) {
					switch triple.Object.(type) {
					case *domain.BlankNode:
						return 500, errors.New("bnodes are not supported!")
					default:
						if pattern.Object.Equal(triple.Object) {
							g.Remove(triple)
							found = true
						}
					}
				}
				if !found {
					return 409, errors.New("no matching triple found in graph!")
				}
			}
		}
	}
	for _, query := range sparql.queries {
		if query.verb == "INSERT" || query.verb == "INSERT DATA" {
			for triple := range query.graph.IterTriples() {
				g.Add(triple)
			}
		}
	}
	return 200, nil
}
