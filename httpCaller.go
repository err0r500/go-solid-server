package gold

import (
	"fmt"
	"net/http"

	"github.com/err0r500/go-solid-server/domain"
)

type HttpCaller interface {
	LoadURI(g *Graph, uri string) (err error)
}

type OrigHttpCaller struct {
	uriManipulator domain.URIManipulator
}

// LoadURI is used to load RDF data from a specific URI
func (o OrigHttpCaller) LoadURI(g *Graph, uri string) (err error) {
	doc := o.uriManipulator.Defrag(uri)
	q, err := http.NewRequest("GET", doc, nil)
	if err != nil {
		return
	}
	q.Header.Set("Accept", "text/turtle,text/n3,application/rdf+xml")
	r, err := httpClient.Do(q)
	if err != nil {
		return
	}
	if r != nil {
		defer r.Body.Close()
		if r.StatusCode == 200 {
			g.ParseBase(r.Body, r.Header.Get("Content-Type"), doc)
		} else {
			err = fmt.Errorf("Could not fetch graph from %s - HTTP %d", uri, r.StatusCode)
		}
	}
	return
}
