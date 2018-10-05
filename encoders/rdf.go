package encoders

import (
	"io"
	"log"

	"github.com/err0r500/go-solid-server/mime"

	"github.com/err0r500/go-solid-server/domain"
	crdf "github.com/presbrey/goraptor"
)

type RdfEncoder struct{}

func (h RdfEncoder) Serialize(g *domain.Graph, mimeS string) (string, error) {
	serializerName := mime.MimeSerializer[mimeS]
	if len(serializerName) == 0 {
		serializerName = "turtle"
	}
	serializer := crdf.NewSerializer(serializerName)
	defer serializer.Free()

	ch := make(chan *crdf.Statement, 1024)
	go func() {
		for triple := range g.IterTriples() {
			ch <- &crdf.Statement{
				Subject:   h.FromDomain(triple.Subject),
				Predicate: h.FromDomain(triple.Predicate),
				Object:    h.FromDomain(triple.Object),
			}
		}
		close(ch)
	}()
	return serializer.Serialize(ch, g.URI())
}

func (RdfEncoder) FromDomain(t domain.Term) crdf.Term {
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

func (RdfEncoder) ToDomain(term crdf.Term) domain.Term {
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

// addStatement adds a Statement object
func (h RdfEncoder) addStatement(g *domain.Graph, st *crdf.Statement) {
	g.AddTriple(h.ToDomain(st.Subject), h.ToDomain(st.Predicate), h.ToDomain(st.Object))
}

func (h RdfEncoder) parse(g *domain.Graph, parserName string, reader io.Reader) {
	parser := crdf.NewParser(parserName)
	parser.SetLogHandler(func(level int, message string) {
		log.Println(message)
	})
	defer parser.Free()
	out := parser.Parse(reader, g.URI())
	for s := range out {
		h.addStatement(g, s)
	}
}
