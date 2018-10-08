package uc

import (
	"strings"

	"github.com/err0r500/go-solid-server/constant"
	"github.com/err0r500/go-solid-server/domain"
)

func (s Interactor) Options(req SafeRequestGetter, resource *domain.PathInfo) *response {
	r := NewResponse()
	// TODO: WAC
	corsReqH := req.HeaderComplete("Access-Control-Request-Headers") // CORS preflight only
	if len(corsReqH) > 0 {
		r.HeaderSet("Access-Control-Allow-Headers", strings.Join(corsReqH, ", "))
	}
	corsReqM := req.HeaderComplete("Access-Control-Request-Method") // CORS preflight only
	if len(corsReqM) > 0 {
		r.HeaderSet("Access-Control-Allow-Methods", strings.Join(corsReqM, ", "))
	} else {
		r.HeaderSet("Access-Control-Allow-Methods", strings.Join(constant.AllMethods(), ", "))
	}

	// set LDP Link headers
	if resource.IsDir {
		r.HeaderAdd("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")
	}
	r.HeaderAdd("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

	// set API Link headers
	r.HeaderAdd("Link", s.uriManipulator.Brack(resource.Base+"/"+constant.SystemPrefix+"/login")+"; rel=\"http://www.w3.org/ns/solid/terms#loginEndpoint\"")
	r.HeaderAdd("Link", s.uriManipulator.Brack(resource.Base+"/"+constant.SystemPrefix+"/logout")+"; rel=\"http://www.w3.org/ns/solid/terms#logoutEndpoint\"")
	r.HeaderAdd("Link", s.uriManipulator.Brack(resource.Base+"/,query")+"; rel=\"http://www.w3.org/ns/solid/terms#twinqlEndpoint\"")
	r.HeaderAdd("Link", s.uriManipulator.Brack(resource.Base+"/,proxy?uri=")+"; rel=\"http://www.w3.org/ns/solid/terms#proxyEndpoint\"")

	return r.respond(200)
}
