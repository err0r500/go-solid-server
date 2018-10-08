package gold

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/err0r500/go-solid-server/reqHandler"

	"github.com/err0r500/go-solid-server/constant"

	"github.com/err0r500/go-solid-server/encoder"

	"github.com/err0r500/go-solid-server/domain"
	"github.com/err0r500/go-solid-server/mime"
	"github.com/err0r500/go-solid-server/uc"
)

// Server object contains http handler, root where the data is found and whether it uses vhosts or not
type Server struct {
	Config domain.ServerConfig

	cookieManager  uc.CookieManager
	logger         uc.Debug
	fileHandler    uc.FilesHandler
	httpCaller     uc.HttpCaller
	mailer         uc.Mailer
	pathInformer   uc.PathInformer
	parser         uc.Encoder
	rdfHandler     encoder.RdfEncoder // fixme : remove this one
	sparqlHandler  uc.SparqlHandler
	templater      uc.Templater
	tokenStorer    uc.TokenStorer
	uriManipulator uc.URIManipulator
	//webdavHandler  uc.WebDavHandler
}

func (s Server) handleStatusText(status int, err error) string {
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
	default: // 501
		return "HTTP 501 - Not implemented\n\n" + err.Error()
	}
}

type response struct {
	status  int
	headers map[string][]string
	argv    []interface{}
}

func (r *response) HeaderAdd(key, value string) {
	r.headers[key] = append(r.headers[key], value)
}

func (r *response) HeaderSet(key, value string) {
	r.headers[key] = []string{value}
}

func (r *response) HeaderDel(key string) {
	r.headers[key] = []string{}
}

func (r *response) respond(status int, a ...interface{}) *response {
	r.status = status
	r.argv = a
	return r
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
	for key, value := range r.headers {
		for _, v := range value {
			w.Header().Add(key, v)
		}
	}

	if r.status > 0 {
		w.WriteHeader(r.status)
	}
	if len(r.argv) > 0 {
		fmt.Fprint(w, r.argv...)
	}
}

// Twinql Query
func TwinqlQuery(w http.ResponseWriter, req uc.SafeRequestGetter, s *Server, user string) *response {
	r := new(response)

	err := s.ProxyReq(w, req, s.Config.QueryTemplate, user)
	if err != nil {
		s.logger.Debug("Query error:", err.Error())
	}

	return r
}

func (s *Server) Options(w http.ResponseWriter, req uc.SafeRequestGetter, resource *domain.PathInfo) *response {
	r := &response{}
	// TODO: WAC
	corsReqH := req.HeaderComplete("Access-Control-Request-Headers") // CORS preflight only
	if len(corsReqH) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(corsReqH, ", "))
	}
	corsReqM := req.HeaderComplete("Access-Control-Request-Method") // CORS preflight only
	if len(corsReqM) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(corsReqM, ", "))
	} else {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(constant.AllMethods(), ", "))
	}

	// set LDP Link headers
	if resource.IsDir {
		w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")
	}
	w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

	// set API Link headers
	w.Header().Add("Link", s.uriManipulator.Brack(resource.Base+"/"+constant.SystemPrefix+"/login")+"; rel=\"http://www.w3.org/ns/solid/terms#loginEndpoint\"")
	w.Header().Add("Link", s.uriManipulator.Brack(resource.Base+"/"+constant.SystemPrefix+"/logout")+"; rel=\"http://www.w3.org/ns/solid/terms#logoutEndpoint\"")
	w.Header().Add("Link", s.uriManipulator.Brack(resource.Base+"/,query")+"; rel=\"http://www.w3.org/ns/solid/terms#twinqlEndpoint\"")
	w.Header().Add("Link", s.uriManipulator.Brack(resource.Base+"/,proxy?uri=")+"; rel=\"http://www.w3.org/ns/solid/terms#proxyEndpoint\"")

	return r.respond(200)
}

func (s Server) GetHead(w http.ResponseWriter, req uc.RequestGetter, resource *domain.PathInfo, contentType string, acl WAC) *response {
	r := &response{}
	var (
		magicType = resource.FileType
		maybeRDF  bool
		glob      bool
		globPath  string
		etag      string
	)

	// check for glob
	glob = false
	if strings.Contains(resource.Obj.Path, "*") {
		glob = true
		path := filepath.Dir(resource.Obj.Path)
		globPath = resource.File
		if path == "." {
			path = ""
		} else {
			path += "/"
		}

		var err error
		resource, err = s.pathInformer.GetPathInfo(resource.Base + "/" + path)
		if err != nil {
			return r.respond(500, err)
		}
	}

	if !resource.Exists {
		return r.respond(404, s.templater.NotFound())
	}

	// First redirect to path + trailing slash if it's missing
	if resource.IsDir && !glob && !strings.HasSuffix(req.BaseURI(), "/") {
		w.Header().Set(constant.HCType, contentType)
		urlStr := resource.URI
		s.logger.Debug("Redirecting to", urlStr)
		http.Redirect(w, req.Request(), urlStr, 301)
		return r
	}

	// overwrite ACL Link header
	w.Header().Set("Link", s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\", "+s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\"")

	// redirect to app
	if s.Config.Vhosts && !resource.Exists && resource.Base == strings.TrimRight(req.BaseURI(), "/") && contentType == constant.TextHtml && req.Method() != "HEAD" {
		w.Header().Set(constant.HCType, contentType)
		urlStr := s.Config.SignUpApp + url.QueryEscape(resource.Obj.Scheme+"://"+resource.Obj.Host+"/"+constant.SystemPrefix+"/accountStatus")
		http.Redirect(w, req.Request(), urlStr, 303)
		return r
	}

	if resource.IsDir {
		w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")
	}
	w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

	status := 501
	aclStatus, err := s.AllowRead(acl, req.Header("Origin"), resource.URI)
	if aclStatus > 200 || err != nil {
		return r.respond(aclStatus, s.handleStatusText(aclStatus, err))
	}

	if req.Method() == "HEAD" {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", resource.Size))
	}

	etag, err = NewETag(resource.File)
	if err != nil {
		return r.respond(500, err)
	}
	w.Header().Set("ETag", "\""+etag+"\"")

	if !req.IfMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}
	if !req.IfNoneMatch("\""+etag+"\"") && contentType != constant.TextHtml {
		// do not return cached views of dirs for html requests
		return r.respond(304, "304 - Not Modified")
	}

	g := domain.NewGraph(resource.URI)
	if resource.IsDir {
		if len(s.Config.DirIndex) > 0 && contentType == constant.TextHtml {

			magicType = constant.TextHtml
			maybeRDF = false
			for _, dirIndex := range s.Config.DirIndex {
				status = 200
				if s.fileHandler.Exists(resource.File + dirIndex) {
					resource, err = s.pathInformer.GetPathInfo(resource.Base + "/" + resource.Path + dirIndex)
					if err != nil {
						return r.respond(500, err)
					}
					w.Header().Set("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
					break
				} else if req.Method() != "HEAD" {
					//TODO load file manager app from local preference file
					w.Header().Set(constant.HCType, contentType)
					urlStr := s.Config.DirApp + resource.Obj.Scheme + "/" + resource.Obj.Host + "/" + resource.Obj.Path + "?" + req.URLRawQuery()

					s.logger.Debug("Redirecting to", urlStr)
					http.Redirect(w, req.Request(), urlStr, 303)
					return r
				}
			}
		} else {
			w.Header().Add("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\"")

			root := domain.NewResource(resource.URI)
			g.AddTriple(root, domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), domain.NewResource("http://www.w3.org/ns/posix/stat#Directory"))
			g.AddTriple(root, domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), domain.NewResource("http://www.w3.org/ns/ldp#Container"))
			g.AddTriple(root, domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), domain.NewResource("http://www.w3.org/ns/ldp#BasicContainer"))

			g.AddTriple(root, domain.NewResource("http://www.w3.org/ns/posix/stat#mtime"), domain.NewLiteral(fmt.Sprintf("%d", resource.ModTime.Unix())))
			g.AddTriple(root, domain.NewResource("http://www.w3.org/ns/posix/stat#size"), domain.NewLiteral(fmt.Sprintf("%d", resource.Size)))

			kb := domain.NewGraph(resource.MetaURI)
			s.fileHandler.UpdateGraphFromFile(kb, s.parser, resource.MetaFile)
			if kb.NotEmpty() {
				for triple := range kb.IterTriples() {
					var subject domain.Term
					if kb.One(domain.NewResource(resource.MetaURI), nil, nil) != nil {
						subject = domain.NewResource(resource.URI)
					} else {
						subject = triple.Subject
					}
					g.AddTriple(subject, triple.Predicate, triple.Object)
				}
			}
			if glob {
				matches, err := filepath.Glob(globPath)
				if err == nil {
					for _, file := range matches {
						res, err := s.pathInformer.GetPathInfo(resource.Base + "/" + filepath.Dir(resource.Path) + "/" + filepath.Base(file))
						if !res.IsDir && res.Exists && err == nil {
							aclStatus, err = s.AllowRead(acl, req.Header("Origin"), res.URI)
							if aclStatus == 200 && err == nil {
								s.fileHandler.AppendFile(g, res.File, res.URI)
								g.AddTriple(root, domain.NewResource("http://www.w3.org/ns/ldp#contains"), domain.NewResource(res.URI))
							}
						}
					}
				}
			} else {
				showContainment := true
				showEmpty := false
				pref := ParsePreferHeader(req.Header("Prefer"))
				if len(pref.headers) > 0 {
					w.Header().Set("Preference-Applied", "return=representation")
				}
				for _, include := range pref.Includes() {
					switch include {
					case "http://www.w3.org/ns/ldp#PreferContainment":
						showContainment = true
					case "http://www.w3.org/ns/ldp#PreferEmptyContainer":
						showEmpty = true
					}
				}
				for _, omit := range pref.Omits() {
					switch omit {
					case "http://www.w3.org/ns/ldp#PreferContainment":
						showContainment = false
					case "http://www.w3.org/ns/ldp#PreferEmptyContainer":
						showEmpty = false
					}
				}

				if infos, err := ioutil.ReadDir(resource.File); err == nil {
					var _s domain.Term
					for _, info := range infos {
						if info != nil {
							// do not list ACLs and Meta files
							if strings.HasSuffix(info.Name(), s.Config.ACLSuffix) || strings.HasSuffix(info.Name(), s.Config.MetaSuffix) {
								continue
							}
							res := resource.URI + info.Name()
							if info.IsDir() {
								res += "/"
							}
							f, err := s.pathInformer.GetPathInfo(res)
							if err != nil {
								r.respond(500, err)
							}
							if info.IsDir() {
								_s = domain.NewResource(f.URI)
								if !showEmpty {
									g.AddTriple(_s, domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), domain.NewResource("http://www.w3.org/ns/ldp#BasicContainer"))
									g.AddTriple(_s, domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), domain.NewResource("http://www.w3.org/ns/ldp#Container"))
								}
								kb := domain.NewGraph(f.URI)
								s.fileHandler.UpdateGraphFromFile(kb, s.parser, f.MetaFile)
								if kb.NotEmpty() {
									for _, st := range kb.All(_s, domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), nil) {
										if st != nil && st.Object != nil {
											g.AddTriple(_s, domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), st.Object)
										}
									}
								}
							} else {
								_s = domain.NewResource(f.URI)
								if !showEmpty {
									g.AddTriple(_s, domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), domain.NewResource("http://www.w3.org/ns/ldp#Resource"))
									// add type if RDF resource

									if f.FileType == constant.TextPlain {
										firstLine, err := s.fileHandler.FileFirstLine(f.File)
										if err != nil {
											s.logger.Debug("scan error :" + err.Error())
										}
										if strings.HasPrefix(firstLine, "@prefix") || strings.HasPrefix(firstLine, "@base") {
											kb := domain.NewGraph(f.URI)
											s.fileHandler.UpdateGraphFromFile(kb, s.parser, f.File)
											if kb.NotEmpty() {
												for _, st := range kb.All(domain.NewResource(f.URI), domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), nil) {
													if st != nil && st.Object != nil {
														g.AddTriple(_s, domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), st.Object)
													}
												}
											}
										}
									}
								}
							}
							if !showEmpty {
								g.AddTriple(_s, domain.NewResource("http://www.w3.org/ns/posix/stat#mtime"), domain.NewLiteral(fmt.Sprintf("%d", info.ModTime().Unix())))
								g.AddTriple(_s, domain.NewResource("http://www.w3.org/ns/posix/stat#size"), domain.NewLiteral(fmt.Sprintf("%d", info.Size())))
							}
							if showContainment {
								g.AddTriple(root, domain.NewResource("http://www.w3.org/ns/ldp#contains"), _s)
							}
						}
					}
				}
			}
			status = 200
			maybeRDF = true
		}
	} else {
		magicType = resource.FileType
		maybeRDF = resource.MaybeRDF
		if len(mime.MimeRdfExt[resource.Extension]) > 0 {
			maybeRDF = true
		}
		if !maybeRDF && magicType == constant.TextPlain {
			maybeRDF = true
		}
		s.logger.Debug("Setting CType to:", magicType)
		status = 200

		if req.Method() == "GET" && strings.Contains(contentType, constant.TextHtml) {
			// delete ETag to force load the app
			w.Header().Del("ETag")
			w.Header().Set("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
			if maybeRDF {
				w.Header().Set(constant.HCType, contentType)
				return r.respond(200, s.templater.Login())
			}
			w.Header().Set(constant.HCType, magicType)
			w.WriteHeader(200)
			f, err := os.Open(resource.File)
			if err == nil {
				defer func() {
					if err := f.Close(); err != nil {
						s.logger.Debug("GET os.Open err: " + err.Error())
					}
				}()
				io.Copy(w, f)
			}
			return r
		}
	}

	if status != 200 {
		return r.respond(status)
	}

	if req.Method() == "HEAD" {
		w.Header().Set(constant.HCType, contentType)
		return r.respond(status)
	}

	if !maybeRDF && len(magicType) > 0 {
		w.Header().Set(constant.HCType, magicType)
		if status != 200 {
			w.WriteHeader(status)
			return r
		}

		f, err := os.Open(resource.File)
		if err == nil {
			defer func() {
				if err := f.Close(); err != nil {
					s.logger.Debug("GET f.Close err:" + err.Error())
				}
			}()
			io.Copy(w, f)
		}

		return r
	}

	if maybeRDF {
		s.fileHandler.UpdateGraphFromFile(g, s.parser, resource.File)
		w.Header().Set(constant.HCType, contentType)
	}

	data, err := s.rdfHandler.Serialize(g, contentType)
	if err != nil {
		return r.respond(500, err)
	} else if len(data) > 0 {
		fmt.Fprint(w, data)
	}

	return r
}

func (s *Server) Patch(w http.ResponseWriter, req uc.SafeRequestGetter, resource *domain.PathInfo, dataHasParser bool, dataMime string, acl WAC) (r *response) {
	r = &response{}

	// check append first
	aclAppend, err := s.AllowAppend(acl, req.Header("Origin"), resource.URI)
	if aclAppend > 200 || err != nil {
		// check if we can write then
		aclWrite, err := s.AllowWrite(acl, req.Header("Origin"), resource.URI)
		if aclWrite > 200 || err != nil {
			return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
		}
	}

	etag, _ := NewETag(resource.File)
	if !req.IfMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}
	if !req.IfNoneMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}

	if dataHasParser {
		s.logger.Debug("Preparing to PATCH resource", resource.URI, "with file", resource.File)
		buf, _ := ioutil.ReadAll(req.Body())
		body := ioutil.NopCloser(bytes.NewBuffer(buf))

		req.Body().Close()

		if req.Header("Content-Length") == "0" || len(buf) == 0 {
			errmsg := "Could not patch resource. No SPARQL statements found in the request."
			s.logger.Debug(errmsg)
			return r.respond(400, errmsg)
		}

		g := domain.NewGraph(resource.URI)
		s.fileHandler.UpdateGraphFromFile(g, s.parser, resource.File)

		switch dataMime {
		case constant.ApplicationJSON:
			s.JSONPatch(g, body)
		case constant.ApplicationSPARQLUpdate:
			if ecode, err := s.sparqlHandler.SPARQLUpdate(g, body); err != nil {
				return r.respond(ecode, "Error processing SPARQL Update: "+err.Error())
			}
		default:
			if dataHasParser {
				s.parser.Parse(g, body, dataMime)
			}
		}

		err = s.fileHandler.SaveGraph(g, resource.File, constant.TextTurtle)
		if err != nil {
			s.logger.Debug("PATCH g.SaveGraph err: " + err.Error())
			return r.respond(500, err)
		}
		s.logger.Debug("succefully patched resource", resource.URI)
		onUpdateURI(resource.URI)
		onUpdateURI(resource.ParentURI)

		return r.respond(200)
	}

	return r.respond(500)
}

func (s Server) Post(w http.ResponseWriter, req uc.SafeRequestGetter, resource *domain.PathInfo, dataHasParser bool, dataMime string, acl WAC) (r *response) {
	r = &response{}

	// check append first
	aclAppend, err := s.AllowAppend(acl, req.Header("Origin"), resource.URI)
	if aclAppend > 200 || err != nil {
		// check if we can write then
		aclWrite, err := s.AllowWrite(acl, req.Header("Origin"), resource.URI)
		if aclWrite > 200 || err != nil {
			return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
		}
	}
	err = nil

	etag, _ := NewETag(resource.File)
	if !req.IfMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}
	if !req.IfNoneMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}

	// LDP
	isNew := false
	if resource.IsDir && dataMime != constant.MultipartFormData {
		link := ParseLinkHeader(req.Header("Link")).MatchRel("type")
		slug := req.Header("Slug")

		uuid := NewUUID()
		uuid = uuid[:6]

		if !strings.HasSuffix(resource.Path, "/") {
			resource.Path += "/"
		}

		if len(slug) > 0 {
			if strings.HasPrefix(slug, "/") {
				slug = strings.TrimLeft(slug, "/")
			}
			if strings.HasSuffix(slug, "/") {
				slug = strings.TrimRight(slug, "/")
			}
			if s.fileHandler.Exists(resource.File + slug) {
				slug += "-" + uuid
			}
		} else {
			slug = uuid
		}
		resource.Path += slug

		if link == "http://www.w3.org/ns/ldp#BasicContainer" {
			if !strings.HasSuffix(resource.Path, "/") {
				resource.Path += "/"
			}
			resource, err = s.pathInformer.GetPathInfo(resource.Base + "/" + resource.Path)
			if err != nil {
				s.logger.Debug("POST LDPC req.pathInfo err: " + err.Error())
				return r.respond(500, err)
			}

			w.Header().Set("Location", resource.URI)
			w.Header().Set("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
			w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")
			w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")

			if err := s.fileHandler.SaveFiles(resource.File, map[string]io.Reader{resource.MetaFile: req.Body()}); err != nil {
				return r.respond(500, err)
			}
			s.logger.Debug("Created dir " + resource.File)

			w.Header().Set("Location", resource.URI)
			onUpdateURI(resource.URI)
			onUpdateURI(resource.ParentURI)
			return r.respond(201)
		}

		resource, err = s.pathInformer.GetPathInfo(resource.Base + "/" + resource.Path)
		if err != nil {
			s.logger.Debug("POST LDPR req.pathInfo err: " + err.Error())
			return r.respond(500, err)
		}
		w.Header().Set("Location", resource.URI)
		w.Header().Set("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
		// LDP header
		w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")
		isNew = true
	}

	if dataMime == constant.MultipartFormData {
		toStore, err := req.MultipartFormContent()
		if err != nil {
			return r.respond(500, err)
		}

		for filename, _ := range toStore {
			location := &url.URL{Path: filename}
			w.Header().Add("Location", resource.URI+location.String())
		}

		if err := s.fileHandler.SaveFiles(resource.File, toStore); err != nil {
			return r.respond(500, err)
		}

		onUpdateURI(resource.URI)
		return r.respond(201)
	} else {
		if !resource.Exists {
			isNew = true
		}
		if resource.IsDir {
			resource.File = resource.File + "/" + s.Config.MetaSuffix
		}

		if dataHasParser {
			g := domain.NewGraph(resource.URI)
			s.fileHandler.UpdateGraphFromFile(g, s.parser, resource.File)

			switch dataMime {
			case constant.ApplicationJSON:
				if err := s.JSONPatch(g, req.Body()); err != nil {
					return r.respond(400, "failed to handle JSONPatch request")
				}
			case constant.ApplicationSPARQLUpdate:
				if ecode, err := s.sparqlHandler.SPARQLUpdate(g, req.Body()); err != nil {
					return r.respond(ecode, "Error processing SPARQL Update: "+err.Error())
				}
			default:
				s.parser.Parse(g, req.Body(), dataMime)
			}

			if err := s.fileHandler.CreateFileOrDir(resource.File); err != nil {
				return r.respond(500, err.Error())
			}

			if g.NotEmpty() {
				err = s.fileHandler.SaveGraph(g, resource.File, constant.TextTurtle)
				if err != nil {
					s.logger.Debug("POST g.SaveGraph err: " + err.Error())
				} else {
					s.logger.Debug("Wrote resource file: " + resource.File)
				}
			}
		} else {
			log.Println("==>>")
			if err := s.fileHandler.SaveFiles(resource.File, map[string]io.Reader{resource.File: req.Body()}); err != nil {
				return r.respond(500, err.Error())
			}
		}

		onUpdateURI(resource.URI)
		if resource.URI != resource.ParentURI {
			onUpdateURI(resource.ParentURI)
		}
		if isNew {
			return r.respond(201)
		}
		return r.respond(200)
	}

	return r.respond(500)
}

func (s Server) Put(w http.ResponseWriter, req uc.RequestGetter, resource *domain.PathInfo, acl WAC) *response {
	r := &response{}
	// LDP header
	w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

	// check append first
	aclAppend, err := s.AllowAppend(acl, req.Header("Origin"), resource.URI)
	if aclAppend > 200 || err != nil {
		// check if we can write then
		aclWrite, err := s.AllowWrite(acl, req.Header("Origin"), resource.URI)
		if aclWrite > 200 || err != nil {
			return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
		}
	}

	etag, _ := NewETag(resource.File)
	if !req.IfMatch("\""+etag+"\"") || !req.IfNoneMatch("\""+etag+"\"") {
		return r.respond(412, "412 - Precondition Failed")
	}

	isNew := true
	if resource.Exists {
		isNew = false
	}

	// LDP PUT should be merged with LDP POST into a common LDP "method" switch
	if ParseLinkHeader(req.Header("Link")).MatchRel("type") == "http://www.w3.org/ns/ldp#BasicContainer" {
		if err := s.fileHandler.CreateFileOrDir(resource.File); err != nil {
			return r.respond(500, err)
		}

		// refresh resource and set the right headers
		newResource, err := s.pathInformer.GetPathInfo(resource.URI)
		if err != nil {
			return r.respond(500, err)
		}
		w.Header().Set("Link", s.uriManipulator.Brack(newResource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(newResource.AclURI)+"; rel=\"acl\"")
		// LDP header
		w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

		onUpdateURI(newResource.URI)
		onUpdateURI(newResource.ParentURI)
		return r.respond(201)
	}

	if resource.IsDir {
		w.Header().Add("Link", s.uriManipulator.Brack(resource.URI)+"; rel=\"describedby\"")
		return r.respond(406, "406 - Cannot use PUT on a directory.")
	}

	if err := s.fileHandler.CreateOrUpdateFile(resource.File, req.Body()); err != nil {
		return r.respond(500, err)
	}

	w.Header().Set("Location", resource.URI)

	onUpdateURI(resource.URI)
	onUpdateURI(resource.ParentURI)
	if isNew {
		return r.respond(201)
	}
	return r.respond(200)
}

func (s Server) Delete(w http.ResponseWriter, req uc.SafeRequestGetter, resource *domain.PathInfo, acl WAC) *response {
	r := &response{}

	aclWrite, err := s.AllowWrite(acl, req.Header("Origin"), resource.URI)
	if aclWrite > 200 || err != nil {
		return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
	}

	if len(resource.Path) == 0 {
		return r.respond(500, "500 - Cannot DELETE root (/)")
	}

	if !s.fileHandler.Exists(resource.File) {
		return r.respond(404, s.templater.NotFound())
	}

	// remove ACL and meta files first
	if resource.File != resource.AclFile {
		s.fileHandler.Delete(resource.AclFile)
	}
	if resource.File != resource.MetaFile {
		s.fileHandler.Delete(resource.MetaFile)
	}
	if err := s.fileHandler.Delete(resource.File); err != nil {
		return r.respond(500, err)
	}

	onDeleteURI(resource.URI)
	onUpdateURI(resource.ParentURI)
	return r
}

func (s Server) MkCol(w http.ResponseWriter, req uc.SafeRequestGetter, resource *domain.PathInfo, acl WAC) *response {
	r := &response{}

	aclWrite, err := s.AllowWrite(acl, req.Header("Origin"), resource.URI)
	if aclWrite > 200 || err != nil {
		return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
	}

	if err := s.fileHandler.CreateFileOrDir(resource.File); err != nil {
		return r.respond(409, err)
	}

	onUpdateURI(resource.URI)
	onUpdateURI(resource.ParentURI)
	return r.respond(201)
}

//func (s *Server) CopyMoveLockUnlock(w http.ResponseWriter, req uc.RequestGetter, resource *domain.PathInfo, acl WAC) (r *response) {
//	respCode, err := s.AllowWrite(acl, req.Header("Origin"), resource.URI)
//	if respCode > 200 || err != nil {
//		return r.respond(respCode, s.handleStatusText(respCode, err))
//	}
//
//	s.webdavHandler.HandleReq(w, req.Request())
//	return nil // should not happen
//}

func (s *Server) handle(w http.ResponseWriter, req uc.RequestGetter) *response {
	r := &response{}
	var err error

	defer func() {
		if rec := recover(); rec != nil {
			s.logger.Debug("\nRecovered from panic: ", rec)
		}
	}()

	// CORS
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Expose-Headers", "User, Location, Link, Vary, Last-Modified, WWW-Authenticate, Content-Length, Content-Type, Accept-Patch, Accept-Post, Allow, Updates-Via, Ms-Author-Via")
	w.Header().Set("Access-Control-Max-Age", "1728000")

	// RWW
	w.Header().Set("MS-Author-Via", "DAV, SPARQL")
	w.Header().Set("Updates-Via", "wss://"+req.Host()+"/")

	// Authentication
	user := s.authn(req, w)
	w.Header().Set("User", user)
	acl := NewWAC(user, req.FormValue("key"))

	// check if is owner
	isOwner := false
	resource, _ := s.pathInformer.GetPathInfo(req.BaseURI())
	if len(user) > 0 {
		if aclStatus, err := s.AllowWrite(acl, req.Header("Origin"), resource.Base); aclStatus == 200 && err == nil {
			isOwner = true
		}
	}

	// Intercept API requests
	if req.TargetsAPI() {
		resp := HandleSystem(w, req, s, user, isOwner)
		if resp.Bytes != nil && len(resp.Bytes) > 0 {
			io.Copy(w, bytes.NewReader(resp.Bytes))
			return r
		}
		return r.respond(resp.Status, resp.Body)
	}

	// Proxy requests
	if strings.HasSuffix(req.URLPath(), constant.ProxyPath) {
		if err := s.ProxyReq(w, req, s.Config.ProxyTemplate+req.FormValue("uri"), user); err != nil {
			s.logger.Debug("Proxy error:", err.Error())
		}
		return r
	}

	// Query requests
	if req.Method() == "POST" && strings.Contains(req.URLPath(), constant.QueryPath) && len(s.Config.QueryTemplate) > 0 {
		return TwinqlQuery(w, req, s, user)
	}

	dataMime := strings.Split(req.Header(constant.HCType), ";")[0]
	dataHasParser := len(mime.MimeParser[dataMime]) > 0
	if len(dataMime) > 0 {
		if dataMime != constant.MultipartFormData && !dataHasParser && req.Method() != "PUT" && req.Method() != "HEAD" && req.Method() != "OPTIONS" {
			s.logger.Debug("Request contains unsupported Media Type:" + dataMime)
			return r.respond(415, "HTTP 415 - Unsupported Media Type:", dataMime)
		}
	}

	// Content Negotiation
	contentType := constant.TextTurtle
	acceptList, _ := req.Accept()
	if len(acceptList) > 0 && acceptList[0].SubType != "*" {
		contentType, err = acceptList.Negotiate(mime.SerializerMimes...)
		if err != nil {
			s.logger.Debug("Accept type not acceptable: " + err.Error())
			return r.respond(406, "HTTP 406 - Accept type not acceptable: "+err.Error())
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
		return s.Options(w, req, resource)
	case "GET", "HEAD":
		return s.GetHead(w, req, resource, contentType, acl)
	case "PATCH":
		return s.Patch(w, req, resource, dataHasParser, dataMime, acl)
	case "POST":
		return s.Post(w, req, resource, dataHasParser, dataMime, acl)
	case "PUT":
		return s.Put(w, req, resource, acl)
	case "DELETE":
		return s.Delete(w, req, resource, acl)
	case "MKCOL":
		s.MkCol(w, req, resource, acl)
	//case "COPY", "MOVE", "LOCK", "UNLOCK":
	//	s.CopyMoveLockUnlock(w, req, resource, acl)
	default:
		return r.respond(405, "405 - Method Not Allowed:", req.Method)
	}
	return r
}

type jsonPatch map[string]map[string][]struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

// JSONPatch is used to perform a PATCH operation on a Graph using data from the reader
func (Server) JSONPatch(g *domain.Graph, r io.Reader) error {
	v := make(jsonPatch)
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	base, _ := url.Parse(g.URI())
	for s, sv := range v {
		su, _ := base.Parse(s)
		for p, pv := range sv {
			pu, _ := base.Parse(p)
			subject := domain.NewResource(su.String())
			predicate := domain.NewResource(pu.String())
			for _, triple := range g.All(subject, predicate, nil) {
				g.Remove(triple)
			}
			for _, o := range pv {
				switch o.Type {
				case "uri":
					g.AddTriple(subject, predicate, domain.NewResource(o.Value))
				case "literal":
					g.AddTriple(subject, predicate, domain.NewLiteral(o.Value))
				default:
					//todo check this : do nothing ??
				}
			}
		}
	}
	return nil
}

func isLocal(host string) bool {
	return strings.HasPrefix(host, "10.") ||
		strings.HasPrefix(host, "172.16.") ||
		strings.HasPrefix(host, "192.168.") ||
		strings.HasPrefix(host, "localhost")
}

// Proxy requests
func (s *Server) ProxyReq(w http.ResponseWriter, req uc.SafeRequestGetter, reqUrl, foundUser string) error {
	uri, err := url.Parse(reqUrl)
	if err != nil {
		return err
	}

	if !s.Config.ProxyLocal && isLocal(uri.Host) {
		return errors.New("Proxying requests to the local network is not allowed.")
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
		token, err := ParseBearerAuthorizationHeader(req.Header(constant.HAuthorization))
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

	// fixme removed proxying for now, enable it again after refactoring
	//req.URL = uri
	//req.Host = uri.Host
	//req.RequestURI = uri.RequestURI()
	//req.Header.Set("User", req.User)
	//proxy.ServeHTTP(w, req.Request())
	return nil
}
