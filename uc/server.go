package uc

import (
	"strings"

	"github.com/err0r500/go-solid-server/domain"
)

type LogicHandler interface {
	Delete(req SafeRequestGetter, resource *domain.PathInfo, acl WAC) *Response
	GetHead(req RequestGetter, resource *domain.PathInfo, contentType string, acl WAC) *Response
	MkCol(req SafeRequestGetter, resource *domain.PathInfo, acl WAC) *Response
	Options(req SafeRequestGetter, resource *domain.PathInfo) *Response
	Patch(req SafeRequestGetter, resource *domain.PathInfo, dataHasParser bool, dataMime string, acl WAC) *Response
	Post(req SafeRequestGetter, resource *domain.PathInfo, dataHasParser bool, dataMime string, acl WAC) *Response
	Put(req RequestGetter, resource *domain.PathInfo, acl WAC) *Response

	AllowRead(acl WAC, origin, path string) (int, error) // fixme unify the interface
	AllowWrite(acl WAC, origin, path string) (int, error)
	AllowControl(acl WAC, origin, path string) (int, error)
	AllowAppend(acl WAC, origin, path string) (int, error)
	VerifyDelegator(delegator string, delegatee string) bool
}

// Interactor object contains http handler, root where the data is found and whether it uses vhosts or not
type Interactor struct {
	Config domain.ServerConfig

	cookieManager  CookieManager
	logger         Debug
	fileHandler    FilesHandler
	httpCaller     HttpCaller
	mailer         Mailer
	pathInformer   PathInformer
	parser         Encoder
	sparqlHandler  SparqlHandler
	templater      Templater
	tokenStorer    TokenStorer
	uriManipulator URIManipulator
	ldpcHandler    LDPCHandler
	uuidGenerator  UUIDGenerator
	authorizer     ACL
}

func (s Interactor) handleStatusText(status int, err error) string {
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
	default:
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

// ParsePreferHeader parses the LDP specific Prefer header
func ParsePreferHeader(header string) *Preferheaders {
	ret := new(Preferheaders)

	for _, v := range strings.Split(header, ",") {
		item := new(preferheader)
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "return=representation") {
			for _, s := range strings.Split(v, ";") {
				s = strings.TrimSpace(s)
				if strings.HasPrefix(s, "omit") {
					s = strings.TrimLeft(s, "omit=")
					s = strings.TrimLeft(s, "\"")
					s = strings.TrimRight(s, "\"")
					item.omit = append(item.omit, strings.Split(s, " ")...)
				}
				if strings.HasPrefix(s, "include") {
					s = strings.TrimLeft(s, "include=")
					s = strings.TrimLeft(s, "\"")
					s = strings.TrimRight(s, "\"")
					item.include = append(item.include, strings.Split(s, " ")...)
				}
			}
			ret.headers = append(ret.headers, item)
		}
	}

	return ret
}

// Omits returns the types of resources to omit when listing an LDPC
func (p *Preferheaders) Omits() []string {
	var ret []string
	for _, v := range p.headers {
		ret = append(ret, v.omit...)
	}
	return ret
}

// Includes returns the types of resources to include when listing an LDPC
func (p *Preferheaders) Includes() []string {
	var ret []string
	for _, v := range p.headers {
		ret = append(ret, v.include...)
	}
	return ret
}

// ParseLinkHeader is a generic Link header parser
func ParseLinkHeader(header string) *Linkheaders {
	ret := new(Linkheaders)

	for _, v := range strings.Split(header, ", ") {
		item := new(linkheader)
		for _, s := range strings.Split(v, ";") {
			s = strings.TrimSpace(s)
			if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
				s = strings.TrimLeft(s, "<")
				s = strings.TrimRight(s, ">")
				item.uri = s
			} else if strings.Contains(s, "rel=") {
				s = strings.TrimLeft(s, "rel=")

				if strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") {
					s = s[1:]
				}
				if strings.HasSuffix(s, "\"") || strings.HasSuffix(s, "'") {
					s = s[:len(s)-1]
				}
				item.rel = s
			}
		}
		ret.headers = append(ret.headers, item)
	}
	return ret
}

// MatchRel attempts to match a Link header based on the rel value
func (l *Linkheaders) MatchRel(rel string) string {
	for _, v := range l.headers {
		if v.rel == rel {
			return v.uri
		}
	}
	return ""
}

// MatchURI attempts to match a Link header based on the href value
func (l *Linkheaders) MatchURI(uri string) bool {
	for _, v := range l.headers {
		if v.uri == uri {
			return true
		}
	}
	return false
}
