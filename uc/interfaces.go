package uc

import (
	"io"

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
