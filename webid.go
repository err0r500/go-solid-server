package gold

import (
	"os"
	"strings"
	"time"

	_path "path"

	"github.com/err0r500/go-solid-server/constant"
	"github.com/err0r500/go-solid-server/domain"
)

//
//import (
//	"crypto/rand"
//	"crypto/rsa"
//	"crypto/sha1"
//	"crypto/tls"
//	"crypto/x509"
//	"encoding/asn1"
//	"encoding/base64"
//	"errors"
//	"fmt"
//	"os"
//	_path "path"
//	"strconv"
//	"strings"
//	"sync"
//	"time"
//	"unicode"
//
//	"github.com/err0r500/go-solid-server/uc"
//
//	"github.com/err0r500/go-solid-server/constant"
//	"github.com/err0r500/go-solid-server/domain"
//)
//
//const (
//	rsaBits = 2048
//)
//
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

func workspaces() []workspace {
	return []workspace{
		{Name: "Preferences", Label: "Preferences workspace", Type: ""},
		{Name: "Applications", Label: "Applications workspace", Type: "PreferencesWorkspace"},
		{Name: "Inbox", Label: "Inbox", Type: ""},
	}
}

// AddCertKeys adds the modulus and exponent values to the profile document
func (s *Server) AddCertKeys(uri string, mod string, exp string) error {
	profileURI := strings.Split(uri, "#")[0]
	resource, _ := s.pathInformer.GetPathInfo(profileURI)
	g := domain.NewGraph(profileURI)

	s.fileHandler.UpdateGraphFromFile(g, s.parser, resource.File)
	keyTerm := domain.NewResource(profileURI + "#key" + s.uuidGen.UUID()[:4])
	g.AddTriple(domain.NewResource(uri), domain.NewNS("cert").Get("key"), keyTerm)
	g.AddTriple(keyTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("cert").Get("RSAPublicKey"))
	g.AddTriple(keyTerm, domain.NewNS("rdfs").Get("label"), domain.NewLiteral("Created "+time.Now().Format(time.RFC822)+" on "+resource.Obj.Host))
	g.AddTriple(keyTerm, domain.NewNS("cert").Get("modulus"), domain.NewLiteralWithDatatype(mod, domain.NewResource("http://www.w3.org/2001/XMLSchema#hexBinary")))
	g.AddTriple(keyTerm, domain.NewNS("cert").Get("exponent"), domain.NewLiteralWithDatatype(exp, domain.NewResource("http://www.w3.org/2001/XMLSchema#int")))

	// write account acl to disk
	serializedGraph, err := s.parser.Serialize(g, constant.TextTurtle)
	if err != nil {
		return err
	}
	if err := s.fileHandler.CreateOrUpdateFile(resource.File, strings.NewReader(serializedGraph)); err != nil {
		return err
	}

	return nil
}

// NewWebIDProfile creates a WebID profile graph based on account data
func NewWebIDProfile(account webidAccount) *domain.Graph {
	profileURI := strings.Split(account.WebID, "#")[0]
	userTerm := domain.NewResource(account.WebID)
	profileTerm := domain.NewResource(profileURI)

	g := domain.NewGraph(profileURI)
	g.AddTriple(profileTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("foaf").Get("PersonalProfileDocument"))
	g.AddTriple(profileTerm, domain.NewNS("foaf").Get("maker"), userTerm)
	g.AddTriple(profileTerm, domain.NewNS("foaf").Get("primaryTopic"), userTerm)

	g.AddTriple(userTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("foaf").Get("Person"))
	if len(account.Name) > 0 {
		g.AddTriple(profileTerm, domain.NewNS("dct").Get("title"), domain.NewLiteral("WebID profile of "+account.Name))
		g.AddTriple(userTerm, domain.NewNS("foaf").Get("name"), domain.NewLiteral(account.Name))
	}
	if len(account.Img) > 0 {
		g.AddTriple(userTerm, domain.NewNS("foaf").Get("img"), domain.NewResource(account.Img))
	}
	if len(account.Agent) > 0 {
		g.AddTriple(userTerm, domain.NewNS("acl").Get("delegates"), domain.NewResource(account.Agent))
	}
	g.AddTriple(userTerm, domain.NewNS("space").Get("storage"), domain.NewResource(account.BaseURI+"/"))
	g.AddTriple(userTerm, domain.NewNS("space").Get("preferencesFile"), domain.NewResource(account.PrefURI))
	g.AddTriple(userTerm, domain.NewNS("st").Get("privateTypeIndex"), domain.NewResource(account.PrivTypeIndex))
	g.AddTriple(userTerm, domain.NewNS("st").Get("publicTypeIndex"), domain.NewResource(account.PubTypeIndex))
	g.AddTriple(userTerm, domain.NewNS("ldp").Get("inbox"), domain.NewResource(account.BaseURI+"/Inbox/"))
	g.AddTriple(userTerm, domain.NewNS("st").Get("timeline"), domain.NewResource(account.BaseURI+"/Timeline/"))

	// add proxy and query endpoints
	if len(account.ProxyURI) > 0 {
		g.AddTriple(userTerm, domain.NewNS("st").Get("proxyTemplate"), domain.NewResource(account.ProxyURI))
	}
	if len(account.QueryURI) > 0 {
		g.AddTriple(userTerm, domain.NewNS("st").Get("queryEndpoint"), domain.NewResource(account.QueryURI))
	}

	return g
}

// LinkToWebID links the account URI (root container) to the WebID that owns the space
func (s *Server) LinkToWebID(account webidAccount) error {
	resource, _ := s.pathInformer.GetPathInfo(account.BaseURI + "/")

	g := domain.NewGraph(resource.URI)
	g.AddTriple(domain.NewResource(account.WebID), domain.NewNS("st").Get("account"), domain.NewResource(resource.URI))

	// write account meta file to disk
	serializedGraph, err := s.parser.Serialize(g, constant.TextTurtle)
	if err != nil {
		return err
	}
	if err := s.fileHandler.CreateOrUpdateFile(resource.MetaFile, strings.NewReader(serializedGraph)); err != nil {
		return err
	}

	return nil
}

func (s *Server) getAccountWebID(baseURI string) string {
	resource, err := s.pathInformer.GetPathInfo(baseURI)
	if err == nil {
		resource, _ = s.pathInformer.GetPathInfo(resource.Base)
		g := domain.NewGraph(resource.MetaURI)
		s.fileHandler.UpdateGraphFromFile(g, s.parser, resource.MetaFile)
		if g.Len() >= 1 {
			webid := g.One(nil, domain.NewNS("st").Get("account"), domain.NewResource(resource.MetaURI))
			if webid != nil {
				return s.uriManipulator.Debrack(webid.Subject.String())
			}
		}
	}

	return ""
}

// AddWorkspaces creates all the necessary workspaces corresponding to a new account
func (s *Server) AddWorkspaces(account webidAccount, containsEmail bool, g *domain.Graph) error {
	pref := domain.NewGraph(account.PrefURI)
	prefTerm := domain.NewResource(account.PrefURI)
	pref.AddTriple(prefTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("space").Get("ConfigurationFile"))
	pref.AddTriple(prefTerm, domain.NewNS("dct").Get("title"), domain.NewLiteral("Preferences file"))

	pref.AddTriple(domain.NewResource(account.WebID), domain.NewNS("space").Get("preferencesFile"), domain.NewResource(account.PrefURI))
	pref.AddTriple(domain.NewResource(account.WebID), domain.NewNS("rdf").Get("type"), domain.NewNS("foaf").Get("Person"))

	for _, ws := range workspaces() {
		resource, _ := s.pathInformer.GetPathInfo(account.BaseURI + "/" + ws.Name + "/")
		err := os.MkdirAll(resource.File, 0755)
		if err != nil {
			return err
		}

		// Write ACLs
		// No one but the user is allowed access by default
		aclTerm := domain.NewResource(resource.AclURI + "#owner")
		wsTerm := domain.NewResource(resource.URI)
		a := domain.NewGraph(resource.AclURI)
		a.AddTriple(aclTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get(constant.HAuthorization))
		a.AddTriple(aclTerm, domain.NewNS("acl").Get("accessTo"), wsTerm)
		a.AddTriple(aclTerm, domain.NewNS("acl").Get("accessTo"), domain.NewResource(resource.AclURI))
		a.AddTriple(aclTerm, domain.NewNS("acl").Get("agent"), domain.NewResource(account.WebID))
		if containsEmail {
			a.AddTriple(aclTerm, domain.NewNS("acl").Get("agent"), domain.NewResource("mailto:"+account.Email))
		}
		a.AddTriple(aclTerm, domain.NewNS("acl").Get("defaultForNew"), wsTerm)
		a.AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Read"))
		a.AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Write"))
		a.AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Control"))
		if ws.Type == "PublicWorkspace" {
			readAllTerm := domain.NewResource(resource.AclURI + "#readall")
			a.AddTriple(readAllTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get(constant.HAuthorization))
			a.AddTriple(readAllTerm, domain.NewNS("acl").Get("accessTo"), wsTerm)
			a.AddTriple(readAllTerm, domain.NewNS("acl").Get("agentClass"), domain.NewNS("foaf").Get("Agent"))
			a.AddTriple(readAllTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Read"))
		}
		// Special case for Inbox (append only)
		if ws.Name == "Inbox" {
			appendAllTerm := domain.NewResource(resource.AclURI + "#apendall")
			a.AddTriple(appendAllTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get(constant.HAuthorization))
			a.AddTriple(appendAllTerm, domain.NewNS("acl").Get("accessTo"), wsTerm)
			a.AddTriple(appendAllTerm, domain.NewNS("acl").Get("agentClass"), domain.NewNS("foaf").Get("Agent"))
			a.AddTriple(appendAllTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Append"))
		}

		// write account acl to disk
		serializedGraph, err := s.parser.Serialize(g, constant.TextTurtle)
		if err != nil {
			return err
		}
		if err := s.fileHandler.CreateOrUpdateFile(resource.AclFile, strings.NewReader(serializedGraph)); err != nil {
			return err
		}

		// Append workspace URL to the preferencesFile
		//if ws.Name != "Inbox" || ws.Name != "Timeline" {
		pref.AddTriple(wsTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("space").Get("Workspace"))
		if len(ws.Type) > 0 {
			pref.AddTriple(wsTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("space").Get(ws.Type))
		}
		pref.AddTriple(wsTerm, domain.NewNS("dct").Get("title"), domain.NewLiteral(ws.Label))

		pref.AddTriple(domain.NewResource(account.WebID), domain.NewNS("space").Get("workspace"), wsTerm)
		//}
	}

	resource, _ := s.pathInformer.GetPathInfo(account.PrefURI)
	err := os.MkdirAll(_path.Dir(resource.File), 0755)
	if err != nil {
		return err
	}

	// write account acl to disk
	serializedGraph, err := s.parser.Serialize(g, constant.TextTurtle)
	if err != nil {
		return err
	}
	if err := s.fileHandler.CreateOrUpdateFile(resource.File, strings.NewReader(serializedGraph)); err != nil {
		return err
	}

	// write the typeIndex
	s.createTypeIndex("ListedDocument", account.PubTypeIndex)
	s.createTypeIndex("UnlistedDocument", account.PrivTypeIndex)

	return nil
}

func (s *Server) createTypeIndex(indexType, url string) error {
	g := domain.NewGraph(url)
	g.AddTriple(domain.NewResource(url), domain.NewNS("rdf").Get("type"), domain.NewNS("st").Get("TypeIndex"))
	g.AddTriple(domain.NewResource(url), domain.NewNS("rdf").Get("type"), domain.NewNS("st").Get(indexType))

	resource, _ := s.pathInformer.GetPathInfo(url)

	// write account acl to disk
	serializedGraph, err := s.parser.Serialize(g, constant.TextTurtle)
	if err != nil {
		return err
	}
	if err := s.fileHandler.CreateOrUpdateFile(resource.File, strings.NewReader(serializedGraph)); err != nil {
		s.logger.Debug("createTypeIndex", err)
	}
	return nil
}
