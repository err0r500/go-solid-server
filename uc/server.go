package uc

import (
	"github.com/err0r500/go-solid-server/domain"
)

// Server object contains http handler, root where the data is found and whether it uses vhosts or not
type Server struct {
	Config domain.ServerConfig

	cookieManager CookieManager
	logger        Debug
	fileHandler   FilesHandler
	httpCaller    HttpCaller
	mailer        Mailer
	pathInformer  PathInformer
	parser        Encoder
	//rdfHandler     encoder.RdfEncoder // fixme : remove this one
	sparqlHandler  SparqlHandler
	templater      Templater
	tokenStorer    TokenStorer
	uriManipulator URIManipulator
}

func (s Server) handleStatusText(status int, err error) string {
	switch status {
	case 200:
		return "HTTP 200 - OK"
	case 401:
		return s.templater.Unauthenticated()
	case 403:
		return s.templater.Unauthorized()
	case 404:
		return "HTTP 404 - Not found\n\n" + err.Error()
	case 500:
		return "HTTP 500 - Internal Server Error\n\n" + err.Error()
	default: // 501
		return "HTTP 501 - Not implemented\n\n" + err.Error()
	}
}

type linkheader struct {
	uri string
	rel string
}

// Linkheaders holds the list of Link headers
type Linkheaders struct {
	headers []*linkheader
}

type preferheader struct {
	omit    []string
	include []string
}

// Preferheaders holds the list of Prefer headers
type Preferheaders struct {
	headers []*preferheader
}
