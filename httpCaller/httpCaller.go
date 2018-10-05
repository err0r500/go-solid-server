package httpCaller

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/err0r500/go-solid-server/encoder"

	"github.com/err0r500/go-solid-server/uc"

	"github.com/err0r500/go-solid-server/domain"
)

type origHttpCaller struct {
	uriManipulator uc.URIManipulator
	encoder        uc.Encoder
}

func New() uc.HttpCaller {
	return origHttpCaller{
		uriManipulator: domain.URIHandler{},
		encoder:        encoder.Facade{},
	}
}

// LoadURI is used to load RDF data from a specific URI
func (o origHttpCaller) LoadURI(g *domain.Graph, uri string) (err error) {
	doc := o.uriManipulator.Defrag(uri)
	q, err := http.NewRequest("GET", doc, nil)
	if err != nil {
		return
	}
	q.Header.Set("Accept", "text/turtle,text/n3,application/rdf+xml")
	r, err := getHttpClient().Do(q)
	if err != nil {
		return
	}
	if r != nil {
		defer r.Body.Close()
		if r.StatusCode == 200 {
			o.encoder.ParseBase(g, r.Body, r.Header.Get("Content-Type"), doc)
		} else {
			err = fmt.Errorf("Could not fetch graph from %s - HTTP %d", uri, r.StatusCode)
		}
	}
	return
}
func getHttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}
