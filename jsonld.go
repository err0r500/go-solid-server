package gold

import (
	"github.com/err0r500/go-solid-server/domain"
	jsonld "github.com/linkeddata/gojsonld"
)

func jterm2term(term jsonld.Term) domain.Term {
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
