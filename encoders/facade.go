package encoders

import (
	"io"

	"github.com/err0r500/go-solid-server/domain"
	"github.com/err0r500/go-solid-server/mime"
	"github.com/err0r500/go-solid-server/uc"
	crdf "github.com/presbrey/goraptor"
)

type Facade struct {
	jsonldEncoder JSONLDEncoder
	rdfEncoder    RdfEncoder
}

func NewMainSerializer() uc.Encoder {
	return Facade{
		jsonldEncoder: JSONLDEncoder{},
		rdfEncoder:    RdfEncoder{},
	}
}

// serialize is used to serialize a graph based on a given mime type
func (f Facade) Serialize(g *domain.Graph, mime string) (string, error) {
	if mime == "application/ld+json" {
		b, err := f.jsonldEncoder.serialize(g, mime)
		return string(b), err
	}

	return f.rdfEncoder.Serialize(g, mime)
}

// ParseBase is used to parse RDF data from a reader, using the provided mime type and a base URI
func (f Facade) ParseBase(g *domain.Graph, reader io.Reader, mimeS string, baseURI string) {
	if len(baseURI) < 1 {
		baseURI = g.URI()
	}

	parserName := mime.MimeParser[mimeS]
	if len(parserName) == 0 {
		parserName = "guess"
	}
	parser := crdf.NewParser(parserName)
	defer parser.Free()
	out := parser.Parse(reader, baseURI)
	for s := range out {
		f.rdfEncoder.addStatement(g, s)
	}
}

func (f Facade) Parse(g *domain.Graph, reader io.Reader, mimeS string) {
	parserName := mime.MimeParser[mimeS]

	switch parserName {
	case "jsonld":
		f.jsonldEncoder.parse(g, reader)
	default:
		if len(parserName) == 0 {
			parserName = "guess"
		}
		f.rdfEncoder.parse(g, parserName, reader)
	}
}
