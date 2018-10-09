package gold

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/err0r500/go-solid-server/uc"

	"github.com/err0r500/go-solid-server/constant"

	"github.com/err0r500/go-solid-server/domain"
)

// SystemReturn is a generic HTTP response specific to system APIs
type SystemReturn struct {
	Status int
	Body   string
	Bytes  []byte
}

type accountRequest struct {
	Method      string
	AccountName string
}

type accountResponse struct {
	AccountURL string `json:"accountURL"`
	Available  bool   `json:"available"`
}

type statusResponse struct {
	Method    string          `json:"method"`
	Status    string          `json:"status"`
	FormURL   string          `json:"formURL"`
	LoginURL  string          `json:"loginURL"`
	LogoutURL string          `json:"logoutURL"`
	Response  accountResponse `json:"response"`
}

// HandleSystem is a router for system specific APIs
func HandleSystem(w http.ResponseWriter, req uc.RequestGetter, s *Server, user string, isOwner bool) SystemReturn {
	if strings.HasSuffix(req.URLPath(), "status") {
		// unsupported yet when server is running on one host
		return accountStatus(w, req, s)
	} else if strings.HasSuffix(req.URLPath(), "new") {
		return newAccount(w, req, s)
	} else if strings.HasSuffix(req.URLPath(), "cert") {
		return newCert(w, req, s)
	} else if strings.HasSuffix(req.URLPath(), "login") {
		return s.logIn(w, req, user)
	} else if strings.HasSuffix(req.URLPath(), "logout") {
		return logOut(w, s)
	} else if strings.HasSuffix(req.URLPath(), "tokens") {
		return accountTokens(req, s, user, isOwner)
	} else if strings.HasSuffix(req.URLPath(), "recovery") {
		return accountRecovery(w, req, s)
	}
	return SystemReturn{Status: 200}
}

func logOut(w http.ResponseWriter, s *Server) SystemReturn {
	s.userCookieDelete(w)
	return SystemReturn{Status: 200, Body: "You have been signed out!"}
}

func (s *Server) logIn(w http.ResponseWriter, req uc.RequestGetter, user string) SystemReturn {
	var passL string
	redirTo := req.FormValue("redirect")
	origin := req.FormValue("origin")

	s.logger.Debug("Got login request. Optional params: ", redirTo, origin)

	// if cookie is set, just redirect
	if len(user) > 0 {
		values := map[string]string{
			"webid":  user,
			"origin": origin,
		}
		// refresh cookie
		err := s.userCookieSet(w, user)
		if err != nil {
			s.logger.Debug("Error setting new cookie: " + err.Error())
			return SystemReturn{Status: 500, Body: err.Error()}
		}
		// redirect
		if len(redirTo) > 0 {
			loginRedirect(w, req, s, values, redirTo)
		}
		return SystemReturn{Status: 200, Body: s.templater.LogoutTemplate(user)}
	}

	webid := req.FormValue("webid")
	passF := req.FormValue("password")

	if req.Method() == "GET" {
		// try to guess WebID from account
		webid = s.getAccountWebID(req.BaseURI())
		return SystemReturn{Status: 200, Body: s.templater.LoginTemplate(redirTo, origin, webid)}
	}

	if len(webid) == 0 && len(passF) == 0 {
		return SystemReturn{Status: 409, Body: "You must supply a valid WebID and password."}
	}
	resource, err := s.pathInformer.GetPathInfo(req.BaseURI())
	if err != nil {
		s.logger.Debug("PathInfo error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	// try to fetch hashed password from root ,acl
	resource, _ = s.pathInformer.GetPathInfo(resource.Base)
	kb := domain.NewGraph(resource.AclURI)
	s.fileHandler.UpdateGraphFromFile(kb, s.parser, resource.AclFile)
	s.logger.Debug("Looking for password in", resource.AclFile)
	// find the policy containing root acl
	for _, m := range kb.All(nil, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Control")) {
		p := kb.One(m.Subject, domain.NewNS("acl").Get("password"), nil)
		if p != nil && kb.One(m.Subject, domain.NewNS("acl").Get("agent"), domain.NewResource(webid)) != nil {
			passL = s.uriManipulator.Unquote(p.Object.String())
			break
		}
	}
	// exit if no pass
	if len(passL) == 0 {
		s.logger.Debug("Access denied! Could not find a password for WebID: " + webid)
		return SystemReturn{Status: 403, Body: "Access denied! Could not find a password for WebID: " + webid}
	}

	// check if passwords match
	passF = saltedPassword(s.Config.Salt, passF)
	if passF != passL {
		s.logger.Debug("Access denied! Bad WebID or password.")
		return SystemReturn{Status: 403, Body: "Access denied! Bad WebID or password."}
	}

	// auth OK
	// also set cookie now
	err = s.userCookieSet(w, webid)
	if err != nil {
		s.logger.Debug("Error setting new cookie: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// handle redirect
	if len(redirTo) > 0 {
		values := map[string]string{
			"webid":  webid,
			"origin": origin,
		}
		loginRedirect(w, req, s, values, redirTo)
	}

	r := req.Request()
	http.Redirect(w, r, r.RequestURI, 301)
	return SystemReturn{Status: 200}
}

func loginRedirect(w http.ResponseWriter, req uc.RequestGetter, s *Server, values map[string]string, redirTo string) SystemReturn {
	key := ""
	// try to get existing token
	key, err := s.tokenStorer.GetTokenByOrigin(constant.HAuthorization, req.Host(), values["origin"])
	if err != nil || len(key) == 0 {
		s.logger.Debug("Could not find a token for origin:", values["origin"])
		key, err = s.tokenStorer.NewPersistedToken(constant.HAuthorization, req.Host(), values)
		if err != nil {
			s.logger.Debug("Could not generate authorization token for " + values["webid"] + ", err: " + err.Error())
			return SystemReturn{Status: 500, Body: "Could not generate auth token for " + values["webid"] + ", err: " + err.Error()}
		}
	}
	s.logger.Debug("Generated new token for", values["webid"], "->", key)
	redir, err := url.Parse(redirTo)
	if err != nil {
		return SystemReturn{Status: 400, Body: "Could not parse URL " + redirTo + ". Error: " + err.Error()}
	}
	q := redir.Query()
	q.Set("webid", values["webid"])
	q.Set("key", key)
	redir.RawQuery = q.Encode()
	s.logger.Debug("Redirecting user to", redir.String())
	http.Redirect(w, req.Request(), redir.String(), 301)
	return SystemReturn{Status: 200}
}

func accountRecovery(w http.ResponseWriter, req uc.SafeRequestGetter, s *Server) SystemReturn {
	if len(req.FormValue("webid")) > 0 && strings.HasPrefix(req.FormValue("webid"), "http") {
		return sendRecoveryToken(req, s)
	} else if len(req.FormValue("token")) > 0 {
		// validate or issue new password
		return validateRecoveryToken(w, req, s)
	}

	// return default app with form
	return SystemReturn{Status: 200, Body: s.templater.AccountRecoveryPage()}
}

func sendRecoveryToken(req uc.SafeRequestGetter, s *Server) SystemReturn {
	webid := req.FormValue("webid")
	// exit if not a local WebID
	// log.Println("Host:" + req.Header.Get("Host"))
	resource, err := s.pathInformer.GetPathInfo(req.BaseURI())
	if err != nil {
		s.logger.Debug("PathInfo error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	// try to fetch recovery email from root ,acl
	resource, _ = s.pathInformer.GetPathInfo(resource.Base)
	email := ""
	kb := domain.NewGraph(resource.AclURI)
	s.fileHandler.UpdateGraphFromFile(kb, s.parser, resource.AclFile)
	// find the policy containing root acl
	for range kb.All(nil, domain.NewNS("acl").Get("accessTo"), domain.NewResource(resource.AclURI)) {
		for _, t := range kb.All(nil, domain.NewNS("acl").Get("agent"), nil) {
			email = s.uriManipulator.Debrack(t.Object.String())
			if strings.HasPrefix(email, "mailto:") {
				email = strings.TrimPrefix(email, "mailto:")
				break
			}
		}
	}
	// exit if no email
	if len(email) == 0 {
		s.logger.Debug("Access denied! Could not find a recovery email for WebID: " + webid)
		return SystemReturn{Status: 403, Body: "Access denied! Could not find a recovery email for WebID: " + webid}
	}
	values := map[string]string{
		"webid": webid,
	}
	// set validity for now + 5 mins
	t := time.Duration(s.Config.TokenAge) * time.Minute
	token, err := s.NewSecureToken("Recovery", values, t)
	if err != nil {
		s.logger.Debug("Could not generate recovery token for " + webid + ", err: " + err.Error())
		return SystemReturn{Status: 400, Body: "Could not generate recovery token for " + webid + ", err: " + err.Error()}
	}
	// create recovery URL
	//IP, _, _ := net.SplitHostPort(req.Request.RemoteAddr)
	link := resource.Base + "/" + constant.SystemPrefix + "/recovery?token=" + encodeQuery(token)
	// Setup message
	params := make(map[string]string)
	params["{{.To}}"] = email
	//params["{{.IP}}"] = IP
	params["{{.Host}}"] = resource.Obj.Host
	//params["{{.From}}"] = s.Config.SMTPConfig.Addr // fixme (should be property of the struct since it's not likely to change)
	params["{{.Link}}"] = link
	go s.mailer.SendRecoveryMail(params)
	return SystemReturn{Status: 200, Body: "You should receive an email shortly with further instructions."}
}

func validateRecoveryToken(w http.ResponseWriter, req uc.SafeRequestGetter, s *Server) SystemReturn {
	token, err := decodeQuery(req.FormValue("token"))
	if err != nil {
		s.logger.Debug("Decode query err: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	value := make(map[string]string)
	err = s.cookieManager.Decode("Recovery", token, &value)
	if err != nil {
		s.logger.Debug("Decoding err: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	if len(value["valid"]) == 0 {
		return SystemReturn{Status: 499, Body: "Missing validity date for token."}
	}
	err = IsTokenDateValid(value["valid"])
	if err != nil {
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	// also set cookie now
	webid := value["webid"]
	err = s.userCookieSet(w, webid)
	if err != nil {
		s.logger.Debug("Error setting new cookie: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	pass := req.FormValue("password")
	verif := req.FormValue("verifypass")
	if len(pass) > 0 && len(verif) > 0 {
		if pass != verif {
			// passwords don't match,
			return SystemReturn{Status: 200, Body: s.templater.NewPassTemplate(token, "Passwords do not match!")}
		}
		// save new password
		resource, _ := s.pathInformer.GetPathInfo(req.BaseURI())
		accountBase := resource.Base + "/"
		resource, _ = s.pathInformer.GetPathInfo(accountBase)

		g := domain.NewGraph(resource.AclURI)
		s.fileHandler.UpdateGraphFromFile(g, s.parser, resource.AclFile)
		// find the policy containing root acl
		for _, m := range g.All(nil, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Control")) {
			p := g.One(m.Subject, domain.NewNS("acl").Get("agent"), domain.NewResource(webid))
			if p != nil {
				passT := g.One(nil, domain.NewNS("acl").Get("password"), nil)
				// remove old password
				if passT != nil {
					g.Remove(passT)
				}
			}
			// add new password
			g.AddTriple(m.Subject, domain.NewNS("acl").Get("password"), domain.NewLiteral(saltedPassword(s.Config.Salt, pass)))

			// write account acl to disk
			serializedAccountAclGraph, err := s.parser.Serialize(g, constant.TextTurtle)
			if err != nil {
				return SystemReturn{Status: 500, Body: err.Error()}
			}
			if err := s.fileHandler.CreateOrUpdateFile(resource.AclFile, strings.NewReader(serializedAccountAclGraph)); err != nil {
				s.logger.Debug("Could not save account acl file with new password. Error: " + err.Error())
				return SystemReturn{Status: 500, Body: err.Error()}
			}
			// All set
			return SystemReturn{Status: 200, Body: "Password saved!"}
			break
		}
	}

	return SystemReturn{Status: 200, Body: s.templater.NewPassTemplate(token, "")}
}

func newAccount(w http.ResponseWriter, req uc.SafeRequestGetter, s *Server) SystemReturn {
	resource, _ := s.pathInformer.GetPathInfo(req.BaseURI())
	host, port, _ := net.SplitHostPort(req.Host())
	if len(host) == 0 {
		host = req.Host()
	}
	if len(port) > 0 {
		port = ":" + port
	}

	accountBase := resource.Base + "/"

	username := strings.ToLower(req.FormValue("username"))
	if !strings.HasPrefix(host, username) {
		accountBase = resource.Base + "/" + username + "/"
		if s.Config.Vhosts == true {
			accountBase = "https://" + username + "." + host + port + "/"
		}
	}

	webidURL := accountBase + "profile/card"
	webidURI := webidURL + "#me"
	resource, _ = s.pathInformer.GetPathInfo(accountBase)

	account := webidAccount{
		Root:          resource.Root,
		BaseURI:       resource.Base,
		Document:      resource.File,
		WebID:         webidURI,
		Agent:         s.Config.Agent,
		PrefURI:       accountBase + "Preferences/prefs.ttl",
		PubTypeIndex:  accountBase + "Preferences/pubTypeIndex.ttl",
		PrivTypeIndex: accountBase + "Preferences/privTypeIndex.ttl",
		Email:         req.FormValue("email"),
		Name:          req.FormValue("name"),
		Img:           req.FormValue("img"),
	}
	if len(s.Config.ProxyTemplate) > 0 {
		account.ProxyURI = accountBase + ",proxy?uri="
	}
	if len(s.Config.QueryTemplate) > 0 {
		account.QueryURI = accountBase + ",query"
	}

	s.logger.Debug("Checking if account profile <" + resource.File + "> exists...")
	stat, err := os.Stat(resource.File)
	if err != nil {
		s.logger.Debug("Stat error: " + err.Error())
	}
	if stat != nil && stat.IsDir() {
		s.logger.Debug("Found " + resource.File)
		return SystemReturn{Status: 406, Body: "An account with the same name already exists."}
	}

	resource, _ = s.pathInformer.GetPathInfo(webidURL)

	// create account space

	// open WebID profile file
	// fixme : check if exists ?
	//f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	//if err != nil {
	//	s.logger.Debug("Open profile error: " + err.Error())
	//	return SystemReturn{Status: 500, Body: err.Error()}
	//}
	//defer f.Close()

	// Generate WebID profile graph for this account
	g := NewWebIDProfile(account)
	// write WebID profile to disk
	serializedAccountGraph, err := s.parser.Serialize(g, constant.TextTurtle)
	if err != nil {
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	if err := s.fileHandler.CreateOrUpdateFile(resource.File, strings.NewReader(serializedAccountGraph)); err != nil {
		s.logger.Debug("Saving profile error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// Write ACL for the profile
	aclTerm := domain.NewResource(resource.AclURI + "#owner")
	g = domain.NewGraph(resource.AclURI)
	g.AddTriple(aclTerm, domain.NewNS("type").Get("type"), domain.NewNS("acl").Get(constant.HAuthorization))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("accessTo"), domain.NewResource(webidURL))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("accessTo"), domain.NewResource(resource.AclURI))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("agent"), domain.NewResource(webidURI))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Read"))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Write"))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Control"))
	readAllTerm := domain.NewResource(resource.AclURI + "#readall")
	g.AddTriple(readAllTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get(constant.HAuthorization))
	g.AddTriple(readAllTerm, domain.NewNS("acl").Get("accessTo"), domain.NewResource(webidURL))
	g.AddTriple(readAllTerm, domain.NewNS("acl").Get("agentClass"), domain.NewNS("foaf").Get("Agent"))
	g.AddTriple(readAllTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Read"))

	// write profile acl to disk
	serializedAclGraph, err := s.parser.Serialize(g, constant.TextTurtle)
	if err != nil {
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	if err := s.fileHandler.CreateOrUpdateFile(resource.AclFile, strings.NewReader(serializedAclGraph)); err != nil {
		s.logger.Debug("Saving profile acl error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// Link from root meta file to the WebID
	err = s.LinkToWebID(account)
	if err != nil {
		s.logger.Debug("Error setting up workspaces: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// Create workspaces and preferencesFile
	err = s.AddWorkspaces(account, len(req.FormValue("email")) > 0, g)
	if err != nil {
		s.logger.Debug("Error setting up workspaces: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// Write default ACL for the whole account space
	// No one but the user is allowed access by default
	resource, _ = s.pathInformer.GetPathInfo(accountBase)
	aclTerm = domain.NewResource(resource.AclURI + "#owner")
	g = domain.NewGraph(resource.AclURI)
	g.AddTriple(aclTerm, domain.NewNS("rdf").Get("type"), domain.NewNS("acl").Get(constant.HAuthorization))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("accessTo"), domain.NewResource(resource.URI))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("accessTo"), domain.NewResource(resource.AclURI))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("agent"), domain.NewResource(webidURI))
	if len(req.FormValue("password")) > 0 {
		g.AddTriple(aclTerm, domain.NewNS("acl").Get("password"), domain.NewLiteral(saltedPassword(s.Config.Salt, req.FormValue("password"))))
	}
	if len(req.FormValue("email")) > 0 {
		g.AddTriple(aclTerm, domain.NewNS("acl").Get("agent"), domain.NewResource("mailto:"+req.FormValue("email")))
	}
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("defaultForNew"), domain.NewResource(resource.URI))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Read"))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Write"))
	g.AddTriple(aclTerm, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Control"))

	// write account acl to disk
	serializedDefaultAclGraph, err := s.parser.Serialize(g, constant.TextTurtle)
	if err != nil {
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	if err := s.fileHandler.CreateOrUpdateFile(resource.AclFile, strings.NewReader(serializedDefaultAclGraph)); err != nil {
		s.logger.Debug("Saving account acl error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}

	// Authenticate the user (set cookie)
	err = s.userCookieSet(w, webidURI)
	if err != nil {
		s.logger.Debug("Error setting new cookie: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	w.Header().Set("User", webidURI)

	// Send welcome email
	if len(req.FormValue("email")) > 0 {
		// Setup message
		params := make(map[string]string)
		params["{{.To}}"] = req.FormValue("email")
		//params["{{.From}}"] = s.Config.SMTPConfig.Addr //  fixme
		params["{{.Name}}"] = account.Name
		params["{{.Host}}"] = resource.Obj.Host
		params["{{.Account}}"] = account.BaseURI
		params["{{.WebID}}"] = account.WebID
		go s.mailer.SendWelcomeMail(params)
	}

	// Generate cert
	// TODO to be deprecated soon
	spkac := req.FormValue("spkac")

	if len(spkac) > 0 {
		// create a new x509 cert based on the SPKAC public key
		certName := account.Name + " [on " + resource.Obj.Host + "]"
		newSpkac, err := NewSPKACx509(webidURI, certName, spkac)
		if err != nil {
			s.logger.Debug("NewSPKACx509 error: " + err.Error())
			return SystemReturn{Status: 500, Body: err.Error()}
		}

		pubKey, err := ParseSPKAC(spkac)
		if err != nil {
			s.logger.Debug("ParseSPKAC error: " + err.Error())
		}
		rsaPub := pubKey.(*rsa.PublicKey)
		mod := fmt.Sprintf("%x", rsaPub.N)
		exp := fmt.Sprintf("%d", rsaPub.E)
		err = s.AddCertKeys(webidURI, mod, exp)
		if err != nil {
			s.logger.Debug("Couldn't add cert keys to profile: " + err.Error())
		}

		ua := req.Header("User-Agent")
		if strings.Contains(ua, "Chrome") {
			w.Header().Set(constant.HCType, "application/x-x509-user-cert; charset=utf-8")
			return SystemReturn{Status: 200, Bytes: newSpkac}
		}
		// Prefer loading cert in iframe, to access onLoad events in the browser for the iframe
		body := `<iframe width="0" height="0" style="display: none;" src="data:application/x-x509-user-cert;base64,` + base64.StdEncoding.EncodeToString(newSpkac) + `"></iframe>`

		return SystemReturn{Status: 200, Body: body}
	}
	return SystemReturn{Status: 200, Body: ""}
}

func newCert(w http.ResponseWriter, req uc.SafeRequestGetter, s *Server) SystemReturn {
	resource, _ := s.pathInformer.GetPathInfo(req.BaseURI())

	name := req.FormValue("name")
	webidURI := req.FormValue("webid")
	spkac := req.FormValue("spkac")

	if len(webidURI) > 0 && len(spkac) > 0 {
		// create a new x509 cert based on the SPKAC public key
		certName := name + " [on " + resource.Obj.Host + "]"
		newSpkac, err := NewSPKACx509(webidURI, certName, spkac)
		if err != nil {
			s.logger.Debug("NewSPKACx509 error: " + err.Error())
			return SystemReturn{Status: 500, Body: err.Error()}
		}
		s.logger.Debug("Generated new cert for " + webidURI)

		// Append cert to profile if it's the case
		loggedUser := w.Header().Get("User")
		s.logger.Debug("Checking if request is authenticated: " + loggedUser)
		if len(loggedUser) > 0 && loggedUser == webidURI && strings.HasPrefix(webidURI, resource.Base) {
			acl := uc.NewWAC(loggedUser, "")
			aclStatus, err := s.i.AllowWrite(acl, req.Header("Origin"), strings.Split(webidURI, "#")[0])
			if aclStatus > 200 || err != nil {
				return SystemReturn{Status: aclStatus, Body: err.Error()}
			}

			pubKey, err := ParseSPKAC(spkac)
			if err != nil {
				s.logger.Debug("ParseSPKAC error: " + err.Error())
				return SystemReturn{Status: 500, Body: err.Error()}
			}
			rsaPub := pubKey.(*rsa.PublicKey)
			mod := fmt.Sprintf("%x", rsaPub.N)
			exp := fmt.Sprintf("%d", rsaPub.E)
			err = s.AddCertKeys(webidURI, mod, exp)
			if err != nil {
				s.logger.Debug("Couldn't add cert keys to profile: " + err.Error())
				return SystemReturn{Status: 500, Body: err.Error()}
			}
			s.logger.Debug("Also added cert public key to " + webidURI)
		} else {
			s.logger.Debug("Not authenticated / local user: " + loggedUser + " != " + webidURI + " on " + resource.Base)
		}

		s.logger.Debug("Done issuing new cert for " + webidURI)

		ua := req.Header("User-Agent")
		if strings.Contains(ua, "Chrome") {
			w.Header().Set(constant.HCType, "application/x-x509-user-cert; charset=utf-8")
			return SystemReturn{Status: 200, Bytes: newSpkac}
		}
		// Prefer loading cert in iframe, to access onLoad events in the browser for the iframe
		body := `<iframe width="0" height="0" style="display: none;" src="data:application/x-x509-user-cert;base64,` + base64.StdEncoding.EncodeToString(newSpkac) + `"></iframe>`

		return SystemReturn{Status: 200, Body: body}
	} else if strings.Contains(req.Header("Accept"), constant.TextHtml) {
		return SystemReturn{Status: 200, Body: s.templater.NewCert()}
	}
	return SystemReturn{Status: 500, Body: "Your request could not be processed. Either no WebID or no SPKAC value was provided."}
}

// accountStatus implements a basic API to check whether a user account exists on the server
// Response object example:
// {
//	method:   "accountStatus",
//  status:   "success",
//  formURL:  "https://example.org/,system/spkac",
//  loginURL: "https://example.org/,system/login/",
//  response: {
//             accountURL: "user",
//             available:   true
//            }
// }
// @@TODO treat exceptions
func accountStatus(w http.ResponseWriter, req uc.SafeRequestGetter, s *Server) SystemReturn {
	resource, _ := s.pathInformer.GetPathInfo(req.BaseURI())
	host, port, _ := net.SplitHostPort(req.Host())
	if len(host) == 0 {
		host = req.Host()
	}
	if len(port) > 0 {
		port = ":" + port
	}

	data, err := ioutil.ReadAll(req.Body())
	if err != nil {
		s.logger.Debug("Read body error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	if len(data) == 0 {
		s.logger.Debug("Empty request for accountStatus API")
		return SystemReturn{Status: 500, Body: "Empty request for accountStatus API"}
	}
	var accReq accountRequest
	err = json.Unmarshal(data, &accReq)
	if err != nil {
		s.logger.Debug("Unmarshal error: " + err.Error())
		return SystemReturn{Status: 500, Body: err.Error()}
	}
	accReq.AccountName = strings.ToLower(accReq.AccountName)

	w.Header().Set(constant.HCType, constant.ApplicationJSON)
	status := "success"
	accName := accReq.AccountName
	accURL := resource.Base + "/" + accName + "/"
	if s.Config.Vhosts {
		accURL = resource.Obj.Scheme + "://" + accName + "." + host + port + "/"
	}
	isAvailable := true
	resource, _ = s.pathInformer.GetPathInfo(accURL)

	s.logger.Debug("Checking if account <" + accReq.AccountName + "> exists...")
	stat, err := os.Stat(resource.File)
	if err != nil {
		s.logger.Debug("Stat error: " + err.Error())
	}
	if stat != nil && stat.IsDir() {
		s.logger.Debug("Found " + s.Config.DataRoot + accName + "." + resource.Root)
		isAvailable = false
	}

	res := statusResponse{
		Method:    "status",
		Status:    status,
		FormURL:   resource.Obj.Scheme + "://" + req.Host() + "/" + constant.SystemPrefix + "/new",
		LoginURL:  accURL + constant.SystemPrefix + "/login",
		LogoutURL: accURL + constant.SystemPrefix + "/logout",
		Response: accountResponse{
			AccountURL: accURL,
			Available:  isAvailable,
		},
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		s.logger.Debug("Marshal error: " + err.Error())
	}
	return SystemReturn{Status: 200, Body: string(jsonData)}
}

func accountTokens(req uc.SafeRequestGetter, s *Server, user string, isOwner bool) SystemReturn {
	if len(user) == 0 {
		return SystemReturn{Status: 401, Body: s.templater.Unauthorized(req.FormValue("redirect"), "")}
	}
	if !isOwner {
		return SystemReturn{Status: 403, Body: "You are not allowed to view this page"}
	}

	tokensHtml := "<div>"

	if len(req.FormValue("revokeAuthz")) > 0 {
		delStatus := "<p style=\"color: green;\">Successfully revoked token!</p>"
		err := s.tokenStorer.DeletePersistedToken(constant.HAuthorization, req.Host(), req.FormValue("revokeAuthz"))
		if err != nil {
			delStatus = "<p>Could not revoke token. Error: " + err.Error() + "</p>"
		}
		tokensHtml += delStatus
	}

	tokens, err := s.tokenStorer.GetTokensByType(constant.HAuthorization, req.Host())
	tokensHtml += "<h2>HAuthorization tokens for applications</h2>\n"
	tokensHtml += "<div>"
	if err == nil {
		for token, values := range tokens {
			tokensHtml += "<p>Token: " + string(token) + "<br>\n"
			tokensHtml += "Application: <strong>" + values["origin"] + "</strong>"
			tokensHtml += " <a href=\"" + req.BaseURI() + "?revokeAuthz=" + encodeQuery(token) + "\">Revoke</a></p>\n"
		}
		tokensHtml += "</ul>\n"
		if len(tokens) == 0 {
			tokensHtml += "No authorization tokens found."
		}
	}

	tokensHtml += "</div>"

	return SystemReturn{Status: 200, Body: s.templater.TokensTemplate(tokensHtml)}
}
