package uc

import (
	"crypto/tls"
	"io"
	"net/http"

	"github.com/err0r500/go-solid-server/domain"
)

// fixme : should handle error and have a better signature
type Mailer interface {
	SendWelcomeMail(params map[string]string)
	SendRecoveryMail(params map[string]string)
}

type Templater interface {
	Login(...string) string
	NewCert(...string) string
	AccountRecoveryPage(...string) string
	Unauthenticated(...string) string
	Unauthorized(...string) string
	NotFound(...string) string
	NewPassTemplate(token, err string, others ...string) string
	LoginTemplate(redir, origin, webid string, others ...string) string
	UnauthorizedTemplate(redirTo, webid string, others ...string) string
	LogoutTemplate(webid string, other ...string) string
	TokensTemplate(tokens string, others ...string) string
}

type Encoder interface {
	Serialize(g *domain.Graph, mime string) (string, error)
	Parse(g *domain.Graph, reader io.Reader, mime string)
	ParseBase(g *domain.Graph, reader io.Reader, mimeS string, baseURI string)
}

type HttpCaller interface {
	LoadURI(g *domain.Graph, uri string) (err error)
}

// Signer creates signatures that verify against a public key.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// Verifier verifies signatures against a public key.
type Verifier interface {
	Verify(data []byte, sig []byte) error
}

type FilesHandler interface {
	CreateFileOrDir(path string) error
	Delete(path string) error
	CreateOrUpdateFile(path string, reader io.Reader) error
	Read(path string) (io.Reader, error)
	FileFirstLine(path string) (string, error)
	SaveFiles(folder string, files map[string]io.Reader) error
	UpdateGraphFromFile(g *domain.Graph, encoder Encoder, filename string)
	AppendFile(g *domain.Graph, filename string, baseURI string)
	Exists(path string) bool
	GetFileContent(path string) ([]byte, error)

	NewETag(path string) (string, error)
}

type URIManipulator interface {
	Brack(s string) string
	Debrack(s string) string
	Defrag(s string) string
	Unquote(s string) string
	ParseBearerAuthorizationHeader(header string) (string, error)
	SplitHostPort(hostport string) (host, port string, err error)
}

type PathInformer interface {
	GetPathInfo(path string) (*domain.PathInfo, error)
}

type ACL interface {
	AllowRead(path string) (int, error)
	AllowWrite(path string) (int, error)
	AllowAppend(path string) (int, error)
	AllowControl(path string) (int, error)
	VerifyDelegator(delegator string, delegatee string) bool
}

type CookieManager interface {
	Encode(name string, value interface{}) (string, error)
	Decode(name, value string, dst interface{}) error
	Check(string) error
	SetSessionCookie(w http.ResponseWriter, user string) error
	DelSessionCookie(w http.ResponseWriter)
}

type TokenStorer interface {
	NewPersistedToken(tokenType, host string, values map[string]string) (string, error)
	GetPersistedToken(tokenType, host, token string) (map[string]string, error)
	GetTokenByOrigin(tokenType, host, origin string) (string, error)
	GetTokensByType(tokenType, host string) (map[string]map[string]string, error)
	DeletePersistedToken(tokenType, host, token string) error
}

type WebDavHandler interface {
	HandleReq(w http.ResponseWriter, r *http.Request)
}

type Debug interface {
	Debug(v ...interface{})
}

type SparqlHandler interface {
	SPARQLUpdate(g *domain.Graph, reader io.Reader) (int, error)
}

type RequestGetter interface {
	SafeRequestGetter
	RequestRawAccessor
}

type SafeRequestGetter interface {
	Headers() map[string][]string
	Header(string) string
	HeaderComplete(string) []string
	Body() io.ReadCloser
	MultipartFormContent() (map[string]io.Reader, error)

	FormValue(key string) string

	IfNoneMatch(etag string) bool
	IfMatch(etag string) bool
	IsTLS() bool
	Method() string

	CookieValue(key string) (string, error)
	Host() string
	TargetsAPI() bool
	BaseURI() string
	URLPath() string
	URLRawQuery() string
	Accept() (domain.AcceptList, error)
}

type RequestRawAccessor interface {
	Request() *http.Request
	TLS() *tls.ConnectionState
}

//type LDPCHandler interface {
//	ParsePreferHeader(header string) *Preferheaders
//	ParseLinkHeader(header string) *Linkheaders
//}

type UUIDGenerator interface {
	UUID() string
}

type Authenticator interface {
	WebIDDigestAuth(req SafeRequestGetter) (string, error)
	WebIDTLSAuth(tls RequestGetter) (string, error)
}

type SpkacHandler interface {
	NewSpkac(certName, spkac, webidURI string) ([]byte, string, string, error)
	ParseSPKAC(spkacBase64 string) (string, string, error)
}
