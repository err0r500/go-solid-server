package gold

import (
	"github.com/err0r500/go-solid-server/domain"
	crdf "github.com/presbrey/goraptor"
)

type Serializer interface {
	Serialize(g *Graph, mime string) (string, error)
}

type RdfHandler struct {
	jsonldSerializer Serializer
	rdfSerializer    Serializer
}

// Serialize is used to serialize a graph based on a given mime type
func (r RdfHandler) Serialize(g *Graph, mime string) (string, error) {
	if mime == "application/ld+json" {
		b, err := r.jsonldSerializer.Serialize(g, mime)
		return string(b), err
	}

	serializerName := mimeSerializer[mime]
	if len(serializerName) == 0 {
		serializerName = "turtle"
	}
	serializer := crdf.NewSerializer(serializerName)
	defer serializer.Free()

	ch := make(chan *crdf.Statement, 1024)
	go func() {
		for triple := range g.IterTriples() {
			ch <- &crdf.Statement{
				Subject:   term2C(triple.Subject),
				Predicate: term2C(triple.Predicate),
				Object:    term2C(triple.Object),
			}
		}
		close(ch)
	}()
	return serializer.Serialize(ch, g.uri)
}

func term2C(t domain.Term) crdf.Term {
	switch t := t.(type) {
	case *domain.BlankNode:
		node := crdf.Blank(t.ID)
		return &node
	case *domain.Resource:
		node := crdf.Uri(t.URI)
		return &node
	case *domain.Literal:
		dt := ""
		if t.Datatype != nil {
			dt = t.Datatype.(*domain.Resource).URI
		}
		node := crdf.Literal{
			Value:    t.Value,
			Datatype: dt,
			Lang:     t.Language,
		}
		return &node
	}
	return nil
}
