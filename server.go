package gold

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/err0r500/go-solid-server/encoder"
	"github.com/err0r500/go-solid-server/reqHandler"

	"github.com/err0r500/go-solid-server/constant"

	"github.com/err0r500/go-solid-server/domain"
	"github.com/err0r500/go-solid-server/mime"
	"github.com/err0r500/go-solid-server/uc"
)

// Server object contains http handler, root where the data is found and whether it uses vhosts or not
type Server struct {
	i      uc.LogicHandler
	Config domain.ServerConfig

	cookieManager  uc.CookieManager
	logger         uc.Debug
	fileHandler    uc.FilesHandler
	httpCaller     uc.HttpCaller
	mailer         uc.Mailer
	pathInformer   uc.PathInformer
	parser         uc.Encoder
	rdfHandler     encoder.RdfEncoder // fixme : remove this one
	templater      uc.Templater
	tokenStorer    uc.TokenStorer
	uriManipulator uc.URIManipulator
	uuidGen        uc.UUIDGenerator
	spkacHandler   uc.SpkacHandler
}

// ServeHTTP handles the response
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// add HSTS
	if s.Config.HSTS {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}

	origins := req.Header["Origin"] // all CORS requests
	if len(origins) > 0 {
		w.Header().Set("Access-Control-Allow-Origin", origins[0])
	} else {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}

	if websocketUpgrade(req) {
		websocketServe(w, req)
		return
	}

	defer func() {
		req.Body.Close()
	}()

	r := s.handle(w, reqHandler.NewRequestGetter(req))
	if r == nil {
		log.Println("received nil response on ", req.Method)
		return
	}

	for key, value := range r.Headers() {
		for _, v := range value {
			w.Header().Add(key, v)
		}
	}
	if r.SessionCookie != "" {
		s.cookieManager.SetSessionCookie(w, r.SessionCookie)
	}
	if r.SessionCookieShouldBeDeleted {
		s.cookieManager.DelSessionCookie(w)
	}
	if ok, newURL := r.ShouldRedirect(); ok {
		http.Redirect(w, req, newURL, r.Status)
	}
	if r.Status > 0 {
		w.WriteHeader(r.Status)
	}
	if r.Bytes != nil {
		io.Copy(w, bytes.NewReader(r.Bytes))
		return //check if body wouldn't be enough
	}
	if len(r.Body) > 0 {
		fmt.Fprint(w, r.Body...)
	}
}

func (s *Server) handle(w http.ResponseWriter, req uc.RequestGetter) *uc.Response {
	var err error

	defer func() {
		if rec := recover(); rec != nil {
			s.logger.Debug("\nRecovered from panic: ", rec)
		}
	}()

	// CORS
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Add("Access-Control-Expose-Headers", "User, Location, Link, Vary, Last-Modified, WWW-Authenticate, Content-Length, Content-Type, Accept-Patch, Accept-Post, Allow, Updates-Via, Ms-Author-Via")
	w.Header().Set("Access-Control-Max-Age", "1728000")

	// RWW
	w.Header().Set("MS-Author-Via", "DAV, SPARQL")
	w.Header().Set("Updates-Via", "wss://"+req.Host()+"/")

	// Authentication
	user := s.i.Authenticate(req)
	if user != "" {
		if len(req.Header("On-Behalf-Of")) > 0 {
			delegator := s.uriManipulator.Debrack(req.Header("On-Behalf-Of"))
			if s.i.VerifyDelegator(delegator, user) {
				s.logger.Debug("Setting delegation user to:", delegator)
				user = delegator
			}
		}
		w.Header().Set("User", user)
		s.userCookieSet(w, user)
	}

	acl := uc.NewWAC(user, req.FormValue("key"))

	// check if is owner
	isOwner := false
	resource, _ := s.pathInformer.GetPathInfo(req.BaseURI())
	if len(user) > 0 {
		if aclStatus, err := s.i.AllowWrite(acl, req.Header("Origin"), resource.Base); aclStatus == 200 && err == nil {
			isOwner = true
		}
	}

	// Intercept API requests
	if req.TargetsAPI() {
		return s.HandleSystem(w, req, user, isOwner)
	}

	// Proxy requests
	if strings.HasSuffix(req.URLPath(), constant.ProxyPath) {
		r := uc.NewResponse()
		if err := s.ProxyReq(w, req, s.Config.ProxyTemplate+req.FormValue("uri"), user); err != nil {
			s.logger.Debug("Proxy error:", err.Error())
		}
		return r
	}

	// Query requests
	if req.Method() == "POST" && strings.Contains(req.URLPath(), constant.QueryPath) && len(s.Config.QueryTemplate) > 0 {
		return s.TwinqlQuery(w, req, user)
	}

	dataMime := strings.Split(req.Header(constant.HCType), ";")[0]
	dataHasParser := len(mime.MimeParser[dataMime]) > 0
	if len(dataMime) > 0 {
		if dataMime != constant.MultipartFormData && !dataHasParser && req.Method() != "PUT" && req.Method() != "HEAD" && req.Method() != "OPTIONS" {
			s.logger.Debug("Request contains unsupported Media Type:" + dataMime)
			return uc.NewResponse().Respond(415, "HTTP 415 - Unsupported Media Type:", dataMime)
		}
	}

	// Content Negotiation
	contentType := constant.TextTurtle
	acceptList, _ := req.Accept()
	if len(acceptList) > 0 && acceptList[0].SubType != "*" {
		contentType, err = acceptList.Negotiate(mime.SerializerMimes...)
		if err != nil {
			s.logger.Debug("Accept type not acceptable: " + err.Error())
			return uc.NewResponse().Respond(406, "HTTP 406 - Accept type not acceptable: "+err.Error())
		}
		//req.AcceptType = contentType // todo : not used ?
	}

	// set ACL Link header
	w.Header().Set("Link", s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\", "+s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\"")

	// generic headers
	w.Header().Set("Accept-Patch", "application/json, application/sparql-update")
	w.Header().Set("Accept-Post", "text/turtle, application/json")
	w.Header().Set("Allow", strings.Join(constant.AllMethods(), ", "))
	w.Header().Set("Vary", "Origin")

	switch req.Method() {
	case "OPTIONS":
		return s.i.Options(req, resource)
	case "GET", "HEAD":
		return s.i.GetHead(req, resource, contentType, acl)
	case "PATCH":
		return s.i.Patch(req, resource, dataHasParser, dataMime, acl)
	case "POST":
		return s.i.Post(req, resource, dataHasParser, dataMime, acl)
	case "PUT":
		return s.i.Put(req, resource, acl)
	case "DELETE":
		return s.i.Delete(req, resource, acl)
	case "MKCOL":
		return s.i.MkCol(req, resource, acl)
		//case "COPY", "MOVE", "LOCK", "UNLOCK":
		//	s.CopyMoveLockUnlock(w, req, resource, acl)
	}

	return uc.NewResponse().Respond(405, "405 - Method Not Allowed:", req.Method)
}

// TwinqlQuery ...
func (s *Server) TwinqlQuery(w http.ResponseWriter, req uc.SafeRequestGetter, user string) *uc.Response {
	r := uc.NewResponse()

	err := s.ProxyReq(w, req, s.Config.QueryTemplate, user)
	if err != nil {
		s.logger.Debug("Query error:", err.Error())
	}

	return r
}

func isLocal(host string) bool {
	return strings.HasPrefix(host, "10.") ||
		strings.HasPrefix(host, "172.16.") ||
		strings.HasPrefix(host, "192.168.") ||
		strings.HasPrefix(host, "localhost")
}

// ProxyReq ...
func (s *Server) ProxyReq(w http.ResponseWriter, req uc.SafeRequestGetter, reqURL, foundUser string) error {
	uri, err := url.Parse(reqURL)
	if err != nil {
		return err
	}

	if !s.Config.ProxyLocal && isLocal(uri.Host) {
		return errors.New("proxying requests to the local network is not allowed")
	}

	if len(req.FormValue("key")) > 0 {
		token, err := decodeQuery(req.FormValue("key"))
		if err != nil {
			s.logger.Debug(err.Error())
		}
		user, err := s.GetAuthzFromToken(token, foundUser, req)
		if err != nil {
			s.logger.Debug(err.Error())
		} else {
			s.logger.Debug("HAuthorization valid for user", user)
		}
		foundUser = user
	}

	if len(req.Header(constant.HAuthorization)) > 0 {
		token, err := s.uriManipulator.ParseBearerAuthorizationHeader(req.Header(constant.HAuthorization))
		if err != nil {
			s.logger.Debug(err.Error())
		}
		user, err := s.GetAuthzFromToken(token, foundUser, req)
		if err != nil {
			s.logger.Debug(err.Error())
		} else {
			s.logger.Debug("HAuthorization valid for user", user)
		}
		foundUser = user
	}

	// fixme : removed proxying for now, enable it again after refactoring
	//req.URL = uri
	//req.Host = uri.Host
	//req.RequestURI = uri.RequestURI()
	//req.Header.Set("User", req.User)
	//proxy.ServeHTTP(w, req.Request())
	return nil
}
