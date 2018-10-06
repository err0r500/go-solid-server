package gold

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	_path "path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/err0r500/go-solid-server/domain"
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

func pkeyTypeNE(pkey interface{}) (t, n, e string) {
	switch pkey := pkey.(type) {
	//TODO: case *dsa.PublicKey
	case *rsa.PublicKey:
		t = "RSAPublicKey"
		n = fmt.Sprintf("%x", pkey.N)
		e = fmt.Sprintf("%d", pkey.E)
	}
	return
}

// WebIDDigestAuth performs a digest authentication using WebID-RSA
func (s *Server) WebIDDigestAuth(req *httpRequest) (string, error) {
	if len(req.Header.Get("Authorization")) == 0 {
		return "", nil
	}

	authH, err := ParseDigestAuthorizationHeader(req.Header.Get("Authorization"))
	if err != nil {
		return "", err
	}

	if len(authH.Source) == 0 || authH.Source != req.BaseURI() {
		return "", errors.New("Bad source URI for auth token: " + authH.Source + " -- possible MITM attack!")
	}

	claim := sha1.Sum([]byte(authH.Source + authH.Username + authH.Nonce))
	signature, err := base64.StdEncoding.DecodeString(authH.Signature)
	if err != nil {
		return "", errors.New(err.Error() + " in " + authH.Signature)
	}

	if len(authH.Username) == 0 || len(claim) == 0 || len(signature) == 0 {
		return "", errors.New("No WebID and/or claim found in the Authorization header.\n" + req.Header.Get("Authorization"))
	}

	// fetch WebID to get pubKey
	if !strings.HasPrefix(authH.Username, "http") {
		return "", errors.New("Username is not a valid HTTP URI: " + authH.Username)
	}

	// Decrypt and validate nonce from secure token
	tValues, err := s.ValidateSecureToken("WWW-Authenticate", authH.Nonce)
	if err != nil {
		return "", err
	}
	v, err := strconv.ParseInt(tValues["valid"], 10, 64)
	if err != nil {
		return "", err
	}
	if time.Now().Local().Unix() > v {
		return "", errors.New("Token expired for " + authH.Username)
	}
	if len(tValues["secret"]) == 0 {
		return "", errors.New("Missing secret from token (tempered with?)")
	}
	if err := s.cookieManager.Check(tValues["secret"]); err != nil {
		return "", err
	}

	g := domain.NewGraph(authH.Username)
	err = s.httpCaller.LoadURI(g, authH.Username)
	if err != nil {
		return "", err
	}

	//req.debug.Println("Checking for public keys for user", authH.Username)
	for _, keyT := range g.All(domain.NewResource(authH.Username), domain.NewNS("cert").Get("key"), nil) {
		for range g.All(keyT.Object, domain.NewNS("rdf").Get("type"), domain.NewNS("cert").Get("RSAPublicKey")) {
			//req.debug.Println("Found RSA key in user's profile", keyT.Object.String())
			for _, pubP := range g.All(keyT.Object, domain.NewNS("cert").Get("pem"), nil) {
				keyP := s.rdfHandler.FromDomain(pubP.Object).String()
				//req.debug.Println("Found matching public key in user's profile", keyP[:10], "...", keyP[len(keyP)-10:len(keyP)])
				parser, err := ParseRSAPublicPEMKey([]byte(keyP))
				if err == nil {
					err = parser.Verify(claim[:], signature)
					if err == nil {
						return authH.Username, nil
					}
				}
				//req.debug.Println("Unable to verify signature with key", keyP[:10], "...", keyP[len(keyP)-10:len(keyP)], "-- reason:", err)
			}
			// also loop through modulus/exp
			for _, pubN := range g.All(keyT.Object, domain.NewNS("cert").Get("modulus"), nil) {
				keyN := s.rdfHandler.FromDomain(pubN.Object).String()
				for _, pubE := range g.All(keyT.Object, domain.NewNS("cert").Get("exponent"), nil) {
					keyE := s.rdfHandler.FromDomain(pubE.Object).String()
					//req.debug.Println("Found matching modulus and exponent in user's profile", keyN[:10], "...", keyN[len(keyN)-10:len(keyN)])
					parser, err := ParseRSAPublicKeyNE("RSAPublicKey", keyN, keyE)
					if err == nil {
						err = parser.Verify(claim[:], signature)
						if err == nil {
							return authH.Username, nil
						}
					}
					//req.debug.Println("Unable to verify signature with key", keyN[:10], "...", keyN[len(keyN)-10:len(keyN)], "-- reason:", err)
				}
			}
		}
	}

	return "", err
}

// WebIDTLSAuth - performs WebID-TLS authentication
func (s *Server) WebIDTLSAuth(tls *tls.ConnectionState) (uri string, err error) {
	claim := ""
	uri = ""
	err = nil

	if tls == nil || !tls.HandshakeComplete {
		return "", errors.New("Not a TLS connection. TLS handshake failed")
	}

	if len(tls.PeerCertificates) < 1 {
		return "", errors.New("No client certificate found in the TLS request!")
	}

	for _, x := range tls.PeerCertificates[0].Extensions {
		if !x.Id.Equal(subjectAltName) {
			continue
		}
		if len(x.Value) < 5 {
			continue
		}

		v := asn1.RawValue{}
		_, err = asn1.Unmarshal(x.Value, &v)
		if err == nil {
			san := ""
			for _, r := range string(v.Bytes[2:]) {
				if rune(r) == 65533 {
					san += ","
				} else if unicode.IsGraphic(rune(r)) {
					san += string(r)
				}
			}
			for _, sanURI := range strings.Split(san, ",") {
				sanURI = strings.TrimSpace(sanURI)
				if len(sanURI) == 0 {
					continue
				}
				if strings.HasPrefix(sanURI, "URI:") {
					claim = strings.TrimSpace(sanURI[4:])
					break
				} else if strings.HasPrefix(sanURI, "http") {
					claim = sanURI
					break
				}
			}
		}
		if len(claim) == 0 || claim[:4] != "http" {
			continue
		}

		pkey := tls.PeerCertificates[0].PublicKey
		t, n, e := pkeyTypeNE(pkey)
		if len(t) == 0 {
			continue
		}

		pkeyk := fmt.Sprint([]string{t, n, e})
		webidL.Lock()
		uri = pkeyURI[pkeyk]
		webidL.Unlock()
		if len(uri) > 0 {
			return
		}

		// pkey from client contains WebID claim

		g := domain.NewGraph(claim)
		err = s.httpCaller.LoadURI(g, claim)
		if err != nil {
			return "", err
		}

		for _, keyT := range g.All(domain.NewResource(claim), domain.NewNS("cert").Get("key"), nil) {
			// found pkey in the profile
			for range g.All(keyT.Object, domain.NewNS("rdf").Get("type"), domain.NewNS("cert").Get(t)) {
				for range g.All(keyT.Object, domain.NewNS("cert").Get("modulus"), domain.NewLiteral(n)) {
					goto matchModulus
				}
				for range g.All(keyT.Object, domain.NewNS("cert").Get("modulus"), domain.NewLiteralWithDatatype(n, domain.NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))) {
					goto matchModulus
				}
			matchModulus:
				// found a matching modulus in the profile
				for range g.All(keyT.Object, domain.NewNS("cert").Get("exponent"), domain.NewLiteral(e)) {
					goto matchExponent
				}
				for range g.All(keyT.Object, domain.NewNS("cert").Get("exponent"), domain.NewLiteralWithDatatype(e, domain.NewResource("http://www.w3.org/2001/XMLSchema#int"))) {
					goto matchExponent
				}
			matchExponent:
				// found a matching exponent in the profile
				//req.debug.Println("Found matching public modulus and exponent in user's profile")
				uri = claim
				webidL.Lock()
				pkeyURI[pkeyk] = uri
				webidL.Unlock()
				return
			}
			// could not find a certificate in the profile
		}
		// could not find a certificate pkey in the profile
	}
	return
}

// WebIDFromCert returns subjectAltName string from x509 []byte
func WebIDFromCert(cert []byte) (string, error) {
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		return "", err
	}

	for _, x := range parsed.Extensions {
		if x.Id.Equal(subjectAltName) {
			v := asn1.RawValue{}
			_, err = asn1.Unmarshal(x.Value, &v)
			if err != nil {
				return "", err
			}
			return string(v.Bytes[2:]), nil
		}
	}
	return "", nil
}

// AddProfileKeys creates a WebID profile graph and corresponding keys
func AddProfileKeys(uri string, g *domain.Graph) (*domain.Graph, *rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, nil, err
	}
	pub := &priv.PublicKey

	profileURI := strings.Split(uri, "#")[0]
	userTerm := domain.NewResource(uri)
	keyTerm := domain.NewResource(profileURI + "#key")

	g.AddTriple(userTerm, domain.NewNS("cert").Get("key"), keyTerm)
	g.AddTriple(keyTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("cert").Get("RSAPublicKey"))
	g.AddTriple(keyTerm, domain.NewNS("dct").Get("title"), domain.NewLiteral("Created  "+time.Now().Format(time.RFC822)))
	g.AddTriple(keyTerm, domain.NewNS("cert").Get("modulus"), domain.NewLiteralWithDatatype(fmt.Sprintf("%x", pub.N), domain.NewResource("http://www.w3.org/2001/XMLSchema#hexBinary")))
	g.AddTriple(keyTerm, domain.NewNS("cert").Get("exponent"), domain.NewLiteralWithDatatype(fmt.Sprintf("%d", pub.E), domain.NewResource("http://www.w3.org/2001/XMLSchema#int")))

	return g, priv, pub, nil
}

// AddCertKeys adds the modulus and exponent values to the profile document
func (s *Server) AddCertKeys(uri string, mod string, exp string) error {
	uuid := NewUUID()
	uuid = uuid[:4]

	profileURI := strings.Split(uri, "#")[0]
	userTerm := domain.NewResource(uri)
	keyTerm := domain.NewResource(profileURI + "#key" + uuid)

	resource, _ := s.pathInformer.GetPathInfo(profileURI)

	g := domain.NewGraph(profileURI)
	s.fileHandler.ReadFile(g, s.parser, resource.File)
	g.AddTriple(userTerm, domain.NewNS("cert").Get("key"), keyTerm)
	g.AddTriple(keyTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("cert").Get("RSAPublicKey"))
	g.AddTriple(keyTerm, domain.NewNS("rdfs").Get("label"), domain.NewLiteral("Created "+time.Now().Format(time.RFC822)+" on "+resource.Obj.Host))
	g.AddTriple(keyTerm, domain.NewNS("cert").Get("modulus"), domain.NewLiteralWithDatatype(mod, domain.NewResource("http://www.w3.org/2001/XMLSchema#hexBinary")))
	g.AddTriple(keyTerm, domain.NewNS("cert").Get("exponent"), domain.NewLiteralWithDatatype(exp, domain.NewResource("http://www.w3.org/2001/XMLSchema#int")))

	// open account acl file
	f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// write account acl to disk
	err = s.fileHandler.WriteFile(g, f, "text/turtle")
	if err != nil {
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

	// open account root meta file
	f, err := os.OpenFile(resource.MetaFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// write account meta file to disk
	err = s.fileHandler.WriteFile(g, f, "text/turtle")
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) getAccountWebID(baseURI string) string {
	resource, err := s.pathInformer.GetPathInfo(baseURI)
	if err == nil {
		resource, _ = s.pathInformer.GetPathInfo(resource.Base)
		g := domain.NewGraph(resource.MetaURI)
		s.fileHandler.ReadFile(g, s.parser, resource.MetaFile)
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

	for _, ws := range workspaces {
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
		a.AddTriple(aclTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get("Authorization"))
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
			a.AddTriple(readAllTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get("Authorization"))
			a.AddTriple(readAllTerm, domain.NewNS("acl").Get("accessTo"), wsTerm)
			a.AddTriple(readAllTerm, domain.NewNS("acl").Get("agentClass"), domain.NewNS("foaf").Get("Agent"))
			a.AddTriple(readAllTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Read"))
		}
		// Special case for Inbox (append only)
		if ws.Name == "Inbox" {
			appendAllTerm := domain.NewResource(resource.AclURI + "#apendall")
			a.AddTriple(appendAllTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get("Authorization"))
			a.AddTriple(appendAllTerm, domain.NewNS("acl").Get("accessTo"), wsTerm)
			a.AddTriple(appendAllTerm, domain.NewNS("acl").Get("agentClass"), domain.NewNS("foaf").Get("Agent"))
			a.AddTriple(appendAllTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Append"))
		}

		// open account acl file
		f, err := os.OpenFile(resource.AclFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()

		// write account acl to disk
		err = s.fileHandler.WriteFile(a, f, "text/turtle")
		if err != nil {
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
	// open account acl file
	f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	// write account acl to disk
	err = s.fileHandler.WriteFile(pref, f, "text/turtle")
	if err != nil {
		return err
	}
	f.Close()

	// write the typeIndex
	s.createTypeIndex("ListedDocument", account.PubTypeIndex)
	s.createTypeIndex("UnlistedDocument", account.PrivTypeIndex)

	return nil
}

func (s *Server) createTypeIndex(indexType, url string) error {
	typeIndex := domain.NewGraph(url)
	typeIndex.AddTriple(domain.NewResource(url), domain.NewNS("rdf").Get("type"), domain.NewNS("st").Get("TypeIndex"))
	typeIndex.AddTriple(domain.NewResource(url), domain.NewNS("rdf").Get("type"), domain.NewNS("st").Get(indexType))

	resource, _ := s.pathInformer.GetPathInfo(url)
	err := os.MkdirAll(_path.Dir(resource.File), 0755)
	if err != nil {
		return err
	}
	// open account acl file
	f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// write account acl to disk
	err = s.fileHandler.WriteFile(typeIndex, f, "text/turtle")
	return err
}
