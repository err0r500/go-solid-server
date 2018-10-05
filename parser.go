package gold

import (
	"github.com/err0r500/go-solid-server/encoders"
)

type OrigParser struct {
	rdfHandler    encoders.RdfEncoder
	jsonldHandler encoders.JSONLDEncoder
}

// Parse is used to parse RDF data from a reader, using the provided mime type
