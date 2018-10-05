package gold

import (
	"bytes"
	"io"
	"log"

	jsonld "github.com/linkeddata/gojsonld"
	crdf "github.com/presbrey/goraptor"
)

type Parser interface {
	Parse(g *Graph, reader io.Reader, mime string)
}

type OrigParser struct{}

// Parse is used to parse RDF data from a reader, using the provided mime type
func (OrigParser) Parse(g *Graph, reader io.Reader, mime string) {
	parserName := mimeParser[mime]
	if len(parserName) == 0 {
		parserName = "guess"
	}
	if parserName == "jsonld" {
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
			g.AddTriple(jterm2term(t.Subject), jterm2term(t.Predicate), jterm2term(t.Object))
		}

	} else {
		parser := crdf.NewParser(parserName)
		parser.SetLogHandler(func(level int, message string) {
			log.Println(message)
		})
		defer parser.Free()
		out := parser.Parse(reader, g.uri)
		for s := range out {
			g.AddStatement(s)
		}
	}
}
