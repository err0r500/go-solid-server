package uc

import (
	"io"
	"os"

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
	WriteFile(g *domain.Graph, file *os.File, mime string) error
	AppendFile(g *domain.Graph, filename string, baseURI string)
	ReadFile(g *domain.Graph, parser Encoder, filename string)
}

type URIManipulator interface {
	Brack(s string) string
	Debrack(s string) string
	Defrag(s string) string
	Unquote(s string) string
}

type PathInformer interface {
	GetPathInfo(path string) (*domain.PathInfo, error)
}
