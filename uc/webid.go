package uc

import (
	"strings"
	"time"

	"github.com/err0r500/go-solid-server/constant"
	"github.com/err0r500/go-solid-server/domain"
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

func workspaces() []workspace {
	return []workspace{
		{Name: "Preferences", Label: "Preferences workspace", Type: ""},
		{Name: "Applications", Label: "Applications workspace", Type: "PreferencesWorkspace"},
		{Name: "Inbox", Label: "Inbox", Type: ""},
	}
}

// AddCertKeys adds the modulus and exponent values to the profile document
func (s Interactor) AddCertKeys(uri string, mod string, exp string) error {
	profileURI := strings.Split(uri, "#")[0]
	resource, _ := s.pathInformer.GetPathInfo(profileURI)
	g := domain.NewGraph(profileURI)

	s.fileHandler.UpdateGraphFromFile(g, s.parser, resource.File)
	keyTerm := domain.NewResource(profileURI + "#key" + s.uuidGenerator.UUID()[:4])
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
func (s Interactor) LinkToWebID(account webidAccount) error {
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

func (s Interactor) GetAccountWebID(baseURI string) string {
	baseResource, err := s.pathInformer.GetPathInfo(baseURI)
	if err != nil {
		return ""
	}

	resource, err := s.pathInformer.GetPathInfo(baseResource.Base)
	if err != nil {
		return ""
	}

	g := domain.NewGraph(resource.MetaURI)
	s.fileHandler.UpdateGraphFromFile(g, s.parser, resource.MetaFile)

	if g.Len() == 0 {
		return ""
	}

	webid := g.One(nil, domain.NewNS("st").Get("account"), domain.NewResource(resource.MetaURI))
	if webid == nil {
		return ""
	}
	return s.uriManipulator.Debrack(webid.Subject.String())
}

// AddWorkspaces creates all the necessary workspaces corresponding to a new account
func (s Interactor) AddWorkspaces(account webidAccount, containsEmail bool, g *domain.Graph) error {
	prefTerm := domain.NewResource(account.PrefURI)
	pref := domain.NewGraph(account.PrefURI).
		AddTriple(prefTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("space").Get("ConfigurationFile")).
		AddTriple(prefTerm, domain.NewNS("dct").Get("title"), domain.NewLiteral("Preferences file")).
		AddTriple(domain.NewResource(account.WebID), domain.NewNS("space").Get("preferencesFile"), domain.NewResource(account.PrefURI)).
		AddTriple(domain.NewResource(account.WebID), domain.NewNS("rdf").Get("type"), domain.NewNS("foaf").Get("Person"))

	for _, ws := range workspaces() {
		resource, _ := s.pathInformer.GetPathInfo(account.BaseURI + "/" + ws.Name + "/")
		s.fileHandler.CreateFileOrDir(resource.File)

		// Write ACLs
		// No one but the user is allowed access by default
		aclTerm := domain.NewResource(resource.AclURI + "#owner")
		wsTerm := domain.NewResource(resource.URI)
		a := domain.NewGraph(resource.AclURI).
			AddTriple(aclTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get(constant.HAuthorization)).
			AddTriple(aclTerm, domain.NewNS("acl").Get("accessTo"), wsTerm).
			AddTriple(aclTerm, domain.NewNS("acl").Get("accessTo"), domain.NewResource(resource.AclURI)).
			AddTriple(aclTerm, domain.NewNS("acl").Get("agent"), domain.NewResource(account.WebID))
		if containsEmail {
			a.AddTriple(aclTerm, domain.NewNS("acl").Get("agent"), domain.NewResource("mailto:"+account.Email))
		}
		a.AddTriple(aclTerm, domain.NewNS("acl").Get("defaultForNew"), wsTerm).
			AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Read")).
			AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Write")).
			AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Control"))
		if ws.Type == "PublicWorkspace" {
			readAllTerm := domain.NewResource(resource.AclURI + "#readall")
			a.AddTriple(readAllTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get(constant.HAuthorization)).
				AddTriple(readAllTerm, domain.NewNS("acl").Get("accessTo"), wsTerm).
				AddTriple(readAllTerm, domain.NewNS("acl").Get("agentClass"), domain.NewNS("foaf").Get("Agent")).
				AddTriple(readAllTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Read"))
		}
		// Special case for Inbox (append only)
		if ws.Name == "Inbox" {
			appendAllTerm := domain.NewResource(resource.AclURI + "#apendall")
			a.AddTriple(appendAllTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get(constant.HAuthorization)).
				AddTriple(appendAllTerm, domain.NewNS("acl").Get("accessTo"), wsTerm).
				AddTriple(appendAllTerm, domain.NewNS("acl").Get("agentClass"), domain.NewNS("foaf").Get("Agent")).
				AddTriple(appendAllTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Append"))
		}

		// write account acl to disk
		serializedAclGraph, err := s.parser.Serialize(a, constant.TextTurtle)
		if err != nil {
			return err
		}
		if err := s.fileHandler.CreateOrUpdateFile(resource.AclFile, strings.NewReader(serializedAclGraph)); err != nil {
			return err
		}

		// Append workspace URL to the preferencesFile
		pref.AddTriple(wsTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("space").Get("Workspace"))
		if len(ws.Type) > 0 {
			pref.AddTriple(wsTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("space").Get(ws.Type))
		}
		pref.AddTriple(wsTerm, domain.NewNS("dct").Get("title"), domain.NewLiteral(ws.Label)).
			AddTriple(domain.NewResource(account.WebID), domain.NewNS("space").Get("workspace"), wsTerm)
	}

	// write account acl to disk
	resource, _ := s.pathInformer.GetPathInfo(account.PrefURI)
	serializedPrefGraph, err := s.parser.Serialize(pref, constant.TextTurtle)
	if err != nil {
		return err
	}
	if err := s.fileHandler.CreateOrUpdateFile(resource.File, strings.NewReader(serializedPrefGraph)); err != nil {
		return err
	}

	// write the typeIndex
	s.CreateTypeIndex("ListedDocument", account.PubTypeIndex)
	s.CreateTypeIndex("UnlistedDocument", account.PrivTypeIndex)

	return nil
}

func (s Interactor) CreateTypeIndex(indexType, url string) error {
	g := domain.NewGraph(url).
		AddTriple(domain.NewResource(url), domain.NewNS("rdf").Get("type"), domain.NewNS("st").Get("TypeIndex")).
		AddTriple(domain.NewResource(url), domain.NewNS("rdf").Get("type"), domain.NewNS("st").Get(indexType))

	// write account acl
	resource, _ := s.pathInformer.GetPathInfo(url)
	serializedGraph, err := s.parser.Serialize(g, constant.TextTurtle)
	if err != nil {
		return err
	}
	if err := s.fileHandler.CreateOrUpdateFile(resource.File, strings.NewReader(serializedGraph)); err != nil {
		s.logger.Debug("CreateTypeIndex", err)
	}
	return nil
}
