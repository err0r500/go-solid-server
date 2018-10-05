package encoder

import (
	"bytes"
	"encoding/json"
	"io"
	"log"

	"github.com/err0r500/go-solid-server/domain"
	jsonld "github.com/linkeddata/gojsonld"
)

type JSONLDEncoder struct{}

func (e JSONLDEncoder) parse(g *domain.Graph, reader io.Reader) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(reader)
	jsonData, err := jsonld.ReadJSON(buf.Bytes())
	options := &jsonld.Options{}
	options.Base = ""
	options.ProduceGeneralizedRdf = false
	dataSet, err := jsonld.ToRDF(jsonData, options)
	if err != nil {
		log.Println(err)
		return
	}

	for t := range dataSet.IterTriples() {
		g.AddTriple(e.ToDomain(t.Subject), e.ToDomain(t.Predicate), e.ToDomain(t.Object))
	}
}

func (JSONLDEncoder) serialize(g *domain.Graph, mime string) (string, error) { // mime not used there but crdf needs it
	var r []map[string]interface{}
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

func (JSONLDEncoder) ToDomain(term jsonld.Term) domain.Term {
	switch term := term.(type) {
	case *jsonld.BlankNode:
		return domain.NewBlankNode(term.RawValue())
	case *jsonld.Literal:
		if term.Datatype != nil && len(term.Datatype.String()) > 0 {
			return domain.NewLiteralWithLanguageAndDatatype(term.Value, term.Language, domain.NewResource(term.Datatype.RawValue()))
		}
		return domain.NewLiteral(term.Value)
	case *jsonld.Resource:
		return domain.NewResource(term.RawValue())
	}
	return nil
}
