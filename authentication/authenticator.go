package authentication

import (
	"sync"
	"time"

	"github.com/err0r500/go-solid-server/encoder"
	"github.com/err0r500/go-solid-server/uc"
)

const (
	rsaBits = 2048
)

type webidAccount struct {
	Root          string
	BaseURI       string
	Document      string
	WebID         string
	PrefURI       string
	PubTypeIndex  string
	PrivTypeIndex string
	Name          string
	Email         string
	Agent         string
	ProxyURI      string
	QueryURI      string
	Img           string
}

type workspace struct {
	Name  string
	Label string
	Type  string
}

var (
	subjectAltName = []int{2, 5, 29, 17}

	notBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)

	workspaces = []workspace{
		{Name: "Preferences", Label: "Preferences workspace", Type: ""},
		{Name: "Applications", Label: "Applications workspace", Type: "PreferencesWorkspace"},
		{Name: "Inbox", Label: "Inbox", Type: ""},
	}

	// cache
	webidL  = new(sync.Mutex)
	pkeyURI = map[string]string{}
)

type authenticator struct {
	httpCaller    uc.HttpCaller
	cookieManager uc.CookieManager
	rdfHandler    encoder.RdfEncoder
}

func New(httpCaller uc.HttpCaller) uc.Authenticator {
	return authenticator{httpCaller: httpCaller}
}
