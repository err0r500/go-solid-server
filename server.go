package gold

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	_path "path"
	"path/filepath"
	"strings"

	"github.com/err0r500/go-solid-server/constant"

	"github.com/err0r500/go-solid-server/encoder"

	"github.com/err0r500/go-solid-server/domain"
	"github.com/err0r500/go-solid-server/mime"
	"github.com/err0r500/go-solid-server/uc"

	"golang.org/x/net/webdav"
)

var (
	debugFlags  = log.Flags() | log.Lshortfile
	debugPrefix = "[debug] "
)

// Server object contains http handler, root where the data is found and whether it uses vhosts or not
type Server struct {
	http.Handler

	Config         domain.ServerConfig
	cookieManager  uc.CookieManager
	debug          *log.Logger // fixme abstract logging
	fileHandler    uc.FilesHandler
	httpCaller     uc.HttpCaller
	mailer         uc.Mailer
	pathInformer   uc.PathInformer
	parser         uc.Encoder
	rdfHandler     encoder.RdfEncoder // fixme : remove this one
	templater      uc.Templater
	tokenStorer    uc.TokenStorer
	uriManipulator uc.URIManipulator
	webdav         *webdav.Handler // fixme move elsewhere ?
}

type httpRequest struct { // fixme attempt to make it purely abstract
	*http.Request
	AcceptType  string
	ContentType string
	User        string
	IsOwner     bool
	wac         WAC
}

func (req httpRequest) BaseURI() string {
	scheme := "http"
	if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
		scheme += "s"
	}
	reqHost := req.Host
	if len(req.Header.Get("X-Forward-Host")) > 0 {
		reqHost = req.Header.Get("X-Forward-Host")
	}
	host, port, err := net.SplitHostPort(reqHost)
	if err != nil {
		host = reqHost
	}
	if len(host) == 0 {
		host = "localhost"
	}
	if len(port) > 0 {
		port = ":" + port
	}
	if (scheme == "https" && port == ":443") || (scheme == "http" && port == ":80") {
		port = ""
	}
	return scheme + "://" + host + port + req.URL.Path
}

func (req httpRequest) ifMatch(etag string) bool {
	if len(etag) == 0 {
		return true
	}
	if len(req.Header.Get("If-Match")) == 0 {
		return true
	}
	val := strings.Split(req.Header.Get("If-Match"), ",")
	for _, v := range val {
		v = strings.TrimSpace(v)
		if v == "*" || v == etag {
			return true
		}
	}
	return false
}

func (req httpRequest) ifNoneMatch(etag string) bool {
	if len(etag) == 0 {
		return true
	}
	if len(req.Header.Get("If-None-Match")) == 0 {
		return true
	}
	val := strings.Split(req.Header.Get("If-None-Match"), ",")
	for _, v := range val {
		v = strings.TrimSpace(v)
		if v != "*" && v != etag {
			return true
		}
	}
	return false
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
	headers http.Header

	argv []interface{}
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

	origin := ""
	origins := req.Header["Origin"] // all CORS requests
	if len(origins) > 0 {
		origin = origins[0]
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	if len(origin) < 1 {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}

	if websocketUpgrade(req) {
		websocketServe(w, req)
		return
	}

	defer func() {
		req.Body.Close()
	}()
	r := s.handle(w, &httpRequest{
		req,
		"",
		"",
		"",
		false,
		WAC{},
	})

	for key := range r.headers {
		w.Header().Set(key, r.headers.Get(key))
	}
	if r.status > 0 {
		w.WriteHeader(r.status)
	}
	if len(r.argv) > 0 {
		fmt.Fprint(w, r.argv...)
	}
}

// Twinql Query
func TwinqlQuery(w http.ResponseWriter, req *httpRequest, s *Server) *response {
	r := new(response)

	err := s.ProxyReq(w, req, s.Config.QueryTemplate)
	if err != nil {
		s.debug.Println("Query error:", err.Error())
	}
	return r
}

func (s *Server) Options(w http.ResponseWriter, req *httpRequest, resource *domain.PathInfo) (r *response) {
	// TODO: WAC
	corsReqH := req.Header["Access-Control-Request-Headers"] // CORS preflight only
	if len(corsReqH) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(corsReqH, ", "))
	}
	corsReqM := req.Header["Access-Control-Request-Method"] // CORS preflight only
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

func (s Server) GetHead(w http.ResponseWriter, req *httpRequest, resource *domain.PathInfo, contentType string, acl WAC) (r *response) {
	unlock := lock(resource.File)
	defer unlock()

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
	if resource.IsDir && glob == false && !strings.HasSuffix(req.BaseURI(), "/") {
		w.Header().Set(constant.HCType, contentType)
		urlStr := resource.URI
		s.debug.Println("Redirecting to", urlStr)
		http.Redirect(w, req.Request, urlStr, 301)
		return
	}

	// overwrite ACL Link header
	w.Header().Set("Link", s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\", "+s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\"")

	// redirect to app
	if s.Config.Vhosts && !resource.Exists && resource.Base == strings.TrimRight(req.BaseURI(), "/") && contentType == constant.TextHtml && req.Method != "HEAD" {
		w.Header().Set(constant.HCType, contentType)
		urlStr := s.Config.SignUpApp + url.QueryEscape(resource.Obj.Scheme+"://"+resource.Obj.Host+"/"+constant.SystemPrefix+"/accountStatus")
		http.Redirect(w, req.Request, urlStr, 303)
		return
	}

	if resource.IsDir {
		w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")
	}
	w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

	status := 501
	aclStatus, err := s.AllowRead(acl, req.Header.Get("Origin"), resource.URI)
	if aclStatus > 200 || err != nil {
		return r.respond(aclStatus, s.handleStatusText(aclStatus, err))
	}

	if req.Method == "HEAD" {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", resource.Size))
	}

	etag, err = NewETag(resource.File)
	if err != nil {
		return r.respond(500, err)
	}
	w.Header().Set("ETag", "\""+etag+"\"")

	if !req.ifMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}
	if !req.ifNoneMatch("\""+etag+"\"") && contentType != constant.TextHtml {
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
				} else if req.Method != "HEAD" {
					//TODO load file manager app from local preference file
					w.Header().Set(constant.HCType, contentType)
					urlStr := s.Config.DirApp + resource.Obj.Scheme + "/" + resource.Obj.Host + "/" + resource.Obj.Path + "?" + req.Request.URL.RawQuery
					s.debug.Println("Redirecting to", urlStr)
					http.Redirect(w, req.Request, urlStr, 303)
					return
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
			s.fileHandler.ReadFile(kb, s.parser, resource.MetaFile)
			if kb.Len() > 0 {
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
							aclStatus, err = s.AllowRead(acl, req.Header.Get("Origin"), res.URI)
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
				pref := ParsePreferHeader(req.Header.Get("Prefer"))
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
								s.fileHandler.ReadFile(kb, s.parser, f.MetaFile)
								if kb.Len() > 0 {
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
									//infoUrl, _ := url.Parse(info.Name())
									guessType := f.FileType

									if guessType == constant.TextPlain {
										// open file and attempt to read the first line
										// Open an input file, exit on error.
										fd, err := os.Open(f.File)
										if err != nil {
											s.debug.Println("GET find mime type error:" + err.Error())
										}
										defer fd.Close()

										scanner := bufio.NewScanner(fd)

										// stop after the first line
										for scanner.Scan() {
											if strings.HasPrefix(scanner.Text(), "@prefix") || strings.HasPrefix(scanner.Text(), "@base") {
												kb := domain.NewGraph(f.URI)
												s.fileHandler.ReadFile(kb, s.parser, f.File)
												if kb.Len() > 0 {
													for _, st := range kb.All(domain.NewResource(f.URI), domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), nil) {
														if st != nil && st.Object != nil {
															g.AddTriple(_s, domain.NewResource("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), st.Object)
														}
													}
												}
											}
											break
										}
										// log potential errors
										if err := scanner.Err(); err != nil {
											s.debug.Println("GET scan err: " + scanner.Err().Error())
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
		s.debug.Println("Setting CType to:", magicType)
		status = 200

		if req.Method == "GET" && strings.Contains(contentType, constant.TextHtml) {
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
						s.debug.Println("GET os.Open err: " + err.Error())
					}
				}()
				io.Copy(w, f)
			}
			return
		}
	}

	if status != 200 {
		return r.respond(status)
	}

	if req.Method == "HEAD" {
		w.Header().Set(constant.HCType, contentType)
		return r.respond(status)
	}

	if !maybeRDF && len(magicType) > 0 {
		w.Header().Set(constant.HCType, magicType)

		if status == 200 {
			f, err := os.Open(resource.File)
			if err == nil {
				defer func() {
					if err := f.Close(); err != nil {
						s.debug.Println("GET f.Close err:" + err.Error())
					}
				}()
				io.Copy(w, f)
			}
		} else {
			w.WriteHeader(status)
		}
		return
	}

	if maybeRDF {
		s.fileHandler.ReadFile(g, s.parser, resource.File)
		w.Header().Set(constant.HCType, contentType)
	}

	data, err := s.rdfHandler.Serialize(g, contentType)
	if err != nil {
		return r.respond(500, err)
	} else if len(data) > 0 {
		fmt.Fprint(w, data)
	}
	return
}

func (s *Server) Patch(w http.ResponseWriter, req *httpRequest, resource *domain.PathInfo, dataHasParser bool, dataMime string, acl WAC) (r *response) {
	unlock := lock(resource.File)
	defer unlock()

	// check append first
	aclAppend, err := s.AllowAppend(acl, req.Header.Get("Origin"), resource.URI)
	if aclAppend > 200 || err != nil {
		// check if we can write then
		aclWrite, err := s.AllowWrite(acl, req.Header.Get("Origin"), resource.URI)
		if aclWrite > 200 || err != nil {
			return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
		}
	}

	etag, _ := NewETag(resource.File)
	if !req.ifMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}
	if !req.ifNoneMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}

	if dataHasParser {
		s.debug.Println("Preparing to PATCH resource", resource.URI, "with file", resource.File)
		buf, _ := ioutil.ReadAll(req.Body)
		body := ioutil.NopCloser(bytes.NewBuffer(buf))

		req.Body.Close()

		if req.Header.Get("Content-Length") == "0" || len(buf) == 0 {
			errmsg := "Could not patch resource. No SPARQL statements found in the request."
			s.debug.Println(errmsg)
			return r.respond(400, errmsg)
		}

		g := domain.NewGraph(resource.URI)
		s.fileHandler.ReadFile(g, s.parser, resource.File)

		switch dataMime {
		case constant.ApplicationJSON:
			s.JSONPatch(g, body)
		case "application/sparql-update":
			sparql := NewSPARQLUpdate(g.URI())
			sparql.Parse(body)
			ecode, err := sparql.SPARQLUpdate(g)
			if err != nil {
				return r.respond(ecode, "Error processing SPARQL Update: "+err.Error())
			}
		default:
			if dataHasParser {
				s.parser.Parse(g, body, dataMime)
			}
		}

		if !resource.Exists {
			err := os.MkdirAll(_path.Dir(resource.File), 0755)
			if err != nil {
				s.debug.Println("PATCH MkdirAll err: " + err.Error())
				return r.respond(500, err)
			}
		}

		f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0664)
		if err != nil {
			s.debug.Println("PATCH os.OpenFile err: " + err.Error())
			return r.respond(500, err)
		}
		defer f.Close()

		err = s.fileHandler.WriteFile(g, f, constant.TextTurtle)
		if err != nil {
			s.debug.Println("PATCH g.WriteFile err: " + err.Error())
			return r.respond(500, err)
		}
		s.debug.Println("Succefully PATCHed resource", resource.URI)
		onUpdateURI(resource.URI)
		onUpdateURI(resource.ParentURI)

		return r.respond(200)
	}

	return r.respond(500)
}

func (s Server) Post(w http.ResponseWriter, req *httpRequest, resource *domain.PathInfo, dataHasParser bool, dataMime string, acl WAC) (r *response) {
	unlock := lock(resource.File)
	defer unlock()
	updateURI := resource.URI

	// check append first
	aclAppend, err := s.AllowAppend(acl, req.Header.Get("Origin"), resource.URI)
	if aclAppend > 200 || err != nil {
		// check if we can write then
		aclWrite, err := s.AllowWrite(acl, req.Header.Get("Origin"), resource.URI)
		if aclWrite > 200 || err != nil {
			return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
		}
	}
	err = nil

	etag, _ := NewETag(resource.File)
	if !req.ifMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}
	if !req.ifNoneMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}

	// LDP
	isNew := false
	if resource.IsDir && dataMime != "multipart/form-data" {
		link := ParseLinkHeader(req.Header.Get("Link")).MatchRel("type")
		slug := req.Header.Get("Slug")

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
			st, err := os.Stat(resource.File + slug)
			//@@TODO append a random string

			if st != nil && !os.IsNotExist(err) {
				slug += "-" + uuid
			}
		} else {
			slug = uuid
		}
		resource.Path += slug

		if len(link) > 0 && link == "http://www.w3.org/ns/ldp#BasicContainer" {
			if !strings.HasSuffix(resource.Path, "/") {
				resource.Path += "/"
			}
			resource, err = s.pathInformer.GetPathInfo(resource.Base + "/" + resource.Path)
			if err != nil {
				s.debug.Println("POST LDPC req.pathInfo err: " + err.Error())
				return r.respond(500, err)
			}

			w.Header().Set("Location", resource.URI)
			w.Header().Set("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
			w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")
			w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")

			err = os.MkdirAll(resource.File, 0755)
			if err != nil {
				s.debug.Println("POST LDPC os.MkdirAll err: " + err.Error())
				return r.respond(500, err)
			}
			s.debug.Println("Created dir " + resource.File)

			buf := new(bytes.Buffer)
			buf.ReadFrom(req.Body)
			if buf.Len() > 0 {
				f, err := os.OpenFile(resource.MetaFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					s.debug.Println("POST LDPC os.OpenFile err: " + err.Error())
					return r.respond(500, err)
				}
				defer f.Close()
				_, err = io.Copy(f, buf)
				if err != nil {
					s.debug.Println("POST io.Copy err: " + err.Error())
				}
			}

			w.Header().Set("Location", resource.URI)
			onUpdateURI(resource.URI)
			onUpdateURI(resource.ParentURI)
			return r.respond(201)
		}

		resource, err = s.pathInformer.GetPathInfo(resource.Base + "/" + resource.Path)
		if err != nil {
			s.debug.Println("POST LDPR req.pathInfo err: " + err.Error())
			return r.respond(500, err)
		}
		w.Header().Set("Location", resource.URI)
		w.Header().Set("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
		// LDP header
		w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")
		isNew = true
	}

	if !resource.Exists {
		err = os.MkdirAll(_path.Dir(resource.File), 0755)
		if err != nil {
			s.debug.Println("POST MkdirAll err: " + err.Error())
			return r.respond(500, err)
		}
		s.debug.Println("Created resource " + _path.Dir(resource.File))
	}

	if dataMime == "multipart/form-data" {
		err := req.ParseMultipartForm(100000)
		if err != nil {
			s.debug.Println("POST parse multipart data err: " + err.Error())
		} else {
			m := req.MultipartForm
			for elt := range m.File {
				files := m.File[elt]
				for i := range files {
					file, err := files[i].Open()
					defer file.Close()
					if err != nil {
						s.debug.Println("POST multipart/form f.Open err: " + err.Error())
						return r.respond(500, err)
					}
					newFile := ""
					if filepath.Base(resource.Path) == files[i].Filename {
						newFile = resource.File
					} else {
						newFile = resource.File + files[i].Filename
					}
					dst, err := os.OpenFile(newFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
					defer dst.Close()
					if err != nil {
						s.debug.Println("POST multipart/form os.Create err: " + err.Error())
						return r.respond(500, err)
					}
					if _, err := io.Copy(dst, file); err != nil {
						s.debug.Println("POST multipart/form io.Copy err: " + err.Error())
						return r.respond(500, err)
					}
					location := &url.URL{Path: files[i].Filename}
					w.Header().Add("Location", resource.URI+location.String())
				}
			}
			onUpdateURI(resource.URI)
			return r.respond(201)
		}
	} else {
		if !resource.Exists {
			isNew = true
		}
		if resource.IsDir {
			resource.File = resource.File + "/" + s.Config.MetaSuffix
		}

		if dataHasParser {
			g := domain.NewGraph(resource.URI)
			s.fileHandler.ReadFile(g, s.parser, resource.File)

			switch dataMime {
			case constant.ApplicationJSON:
				s.JSONPatch(g, req.Body)
			case "application/sparql-update":
				sparql := NewSPARQLUpdate(g.URI())
				sparql.Parse(req.Body)
				ecode, err := sparql.SPARQLUpdate(g)
				if err != nil {
					println(err.Error())
					return r.respond(ecode, "Error processing SPARQL Update: "+err.Error())
				}
			default:
				s.parser.Parse(g, req.Body, dataMime)
			}
			f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				s.debug.Println("POST os.OpenFile err: " + err.Error())
				return r.respond(500, err.Error())
			}
			defer f.Close()
			if g.Len() > 0 {
				err = s.fileHandler.WriteFile(g, f, constant.TextTurtle)
				if err != nil {
					s.debug.Println("POST g.WriteFile err: " + err.Error())
				} else {
					s.debug.Println("Wrote resource file: " + resource.File)
				}
			}
		} else {
			f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				s.debug.Println("POST os.OpenFile err: " + err.Error())
				return r.respond(500, err.Error())
			}
			defer f.Close()
			_, err = io.Copy(f, req.Body)
			if err != nil {
				s.debug.Println("POST os.OpenFile err: " + err.Error())
				return r.respond(500, err.Error())
			}
		}

		onUpdateURI(updateURI)
		if updateURI != resource.ParentURI {
			onUpdateURI(resource.ParentURI)
		}
		if isNew {
			return r.respond(201)
		}
		return r.respond(200)
	}

	return r.respond(500)
}

func (s Server) Put(w http.ResponseWriter, req *httpRequest, resource *domain.PathInfo, acl WAC) (r *response) {
	unlock := lock(resource.File)
	defer unlock()

	// LDP header
	w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

	// check append first
	aclAppend, err := s.AllowAppend(acl, req.Header.Get("Origin"), resource.URI)
	if aclAppend > 200 || err != nil {
		// check if we can write then
		aclWrite, err := s.AllowWrite(acl, req.Header.Get("Origin"), resource.URI)
		if aclWrite > 200 || err != nil {
			return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
		}
	}

	etag, _ := NewETag(resource.File)
	if !req.ifMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}
	if !req.ifNoneMatch("\"" + etag + "\"") {
		return r.respond(412, "412 - Precondition Failed")
	}

	isNew := true
	if resource.Exists {
		isNew = false
	}

	// LDP PUT should be merged with LDP POST into a common LDP "method" switch
	link := ParseLinkHeader(req.Header.Get("Link")).MatchRel("type")
	if len(link) > 0 && link == "http://www.w3.org/ns/ldp#BasicContainer" {
		err := os.MkdirAll(resource.File, 0755)
		if err != nil {
			s.debug.Println("PUT MkdirAll err: " + err.Error())
			return r.respond(500, err)
		}
		// refresh resource and set the right headers
		resource, err = s.pathInformer.GetPathInfo(resource.URI)
		w.Header().Set("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
		// LDP header
		w.Header().Add("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

		onUpdateURI(resource.URI)
		onUpdateURI(resource.ParentURI)
		return r.respond(201)
	}
	err = os.MkdirAll(_path.Dir(resource.File), 0755)
	if err != nil {
		s.debug.Println("PUT MkdirAll err: " + err.Error())
		return r.respond(500, err)
	}

	f, err := os.OpenFile(resource.File, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		s.debug.Println("PUT os.OpenFile err: " + err.Error())
		if resource.IsDir {
			w.Header().Add("Link", s.uriManipulator.Brack(resource.URI)+"; rel=\"describedby\"")
			return r.respond(406, "406 - Cannot use PUT on a directory.")
		}
		return r.respond(500, err)
	}
	defer f.Close()

	_, err = io.Copy(f, req.Body)
	if err != nil {
		s.debug.Println("PUT io.Copy err: " + err.Error())
	}

	if err != nil {
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

func (s Server) Delete(w http.ResponseWriter, req *httpRequest, resource *domain.PathInfo, acl WAC) (r *response) {
	unlock := lock(resource.Path)
	defer unlock()

	aclWrite, err := s.AllowWrite(acl, req.Header.Get("Origin"), resource.URI)
	if aclWrite > 200 || err != nil {
		return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
	}

	if len(resource.Path) == 0 {
		return r.respond(500, "500 - Cannot DELETE root (/)")
	}
	// remove ACL and meta files first
	if resource.File != resource.AclFile {
		_ = os.Remove(resource.AclFile)
	}
	if resource.File != resource.MetaFile {
		_ = os.Remove(resource.MetaFile)
	}
	err = os.Remove(resource.File)
	if err != nil {
		if os.IsNotExist(err) {
			return r.respond(404, s.templater.NotFound())
		}
		return r.respond(500, err)
	}
	_, err = os.Stat(resource.File)
	if err == nil {
		return r.respond(409, err)
	}
	onDeleteURI(resource.URI)
	onUpdateURI(resource.ParentURI)
	return
}

func (s Server) MkCol(w http.ResponseWriter, req *httpRequest, resource *domain.PathInfo, acl WAC) (r *response) {
	unlock := lock(resource.File)
	defer unlock()

	aclWrite, err := s.AllowWrite(acl, req.Header.Get("Origin"), resource.URI)
	if aclWrite > 200 || err != nil {
		return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
	}

	err = os.MkdirAll(resource.File, 0755)
	if err != nil {
		switch err.(type) {
		case *os.PathError:
			return r.respond(409, err)
		default:
			return r.respond(500, err)
		}
	} else {
		_, err := os.Stat(resource.File)
		if err != nil {
			return r.respond(409, err)
		}
	}
	onUpdateURI(resource.URI)
	onUpdateURI(resource.ParentURI)
	return r.respond(201)
}

func (s *Server) CopyMoveLockUnlock(w http.ResponseWriter, req *httpRequest, resource *domain.PathInfo, acl WAC) (r *response) {
	aclWrite, err := s.AllowWrite(acl, req.Header.Get("Origin"), resource.URI)
	if aclWrite > 200 || err != nil {
		return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
	}

	s.webdav.ServeHTTP(w, req.Request)
	return
}

func (s *Server) handle(w http.ResponseWriter, req *httpRequest) (r *response) {
	r = new(response)
	var err error

	defer func() {
		if rec := recover(); rec != nil {
			s.debug.Println("\nRecovered from panic: ", rec)
		}
	}()

	s.debug.Println("\n------ New " + req.Method + " request from " + req.RemoteAddr + " ------")

	// CORS
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Expose-Headers", "User, Location, Link, Vary, Last-Modified, WWW-Authenticate, Content-Length, Content-Type, Accept-Patch, Accept-Post, Allow, Updates-Via, Ms-Author-Via")
	w.Header().Set("Access-Control-Max-Age", "1728000")

	// RWW
	w.Header().Set("MS-Author-Via", "DAV, SPARQL")
	w.Header().Set("Updates-Via", "wss://"+req.Host+"/")

	// Authentication
	user := s.authn(req, w)
	req.User = user
	w.Header().Set("User", user)
	acl := NewWAC(user, req.Request.FormValue("key"))

	// check if is owner
	req.IsOwner = false
	resource, _ := s.pathInformer.GetPathInfo(req.BaseURI())
	if len(user) > 0 {
		if aclStatus, err := s.AllowWrite(acl, req.Header.Get("Origin"), resource.Base); aclStatus == 200 && err == nil {
			req.IsOwner = true
		}
	}

	// Intercept API requests
	if strings.Contains(req.Request.URL.Path, "/"+constant.SystemPrefix) && req.Method != "OPTIONS" {
		resp := HandleSystem(w, req, s)
		if resp.Bytes != nil && len(resp.Bytes) > 0 {
			// copy raw bytes
			io.Copy(w, bytes.NewReader(resp.Bytes))
			return
		}
		return r.respond(resp.Status, resp.Body)
	}

	// Proxy requests
	if strings.HasSuffix(req.URL.Path, constant.ProxyPath) {
		err = s.ProxyReq(w, req, s.Config.ProxyTemplate+req.FormValue("uri"))
		if err != nil {
			s.debug.Println("Proxy error:", err.Error())
		}
		return
	}

	// Query requests
	if req.Method == "POST" && strings.Contains(req.URL.Path, constant.QueryPath) && len(s.Config.QueryTemplate) > 0 {
		return TwinqlQuery(w, req, s)
	}

	//s.debug.Println(req.RemoteAddr + " requested resource URI: " + req.URL.String())
	//s.debug.Println(req.RemoteAddr + " requested resource Path: " + resource.File)

	dataMime := req.Header.Get(constant.HCType)
	dataMime = strings.Split(dataMime, ";")[0]
	dataHasParser := len(mime.MimeParser[dataMime]) > 0
	if len(dataMime) > 0 {
		s.debug.Println("Content-Type: " + dataMime)
		if dataMime != "multipart/form-data" && !dataHasParser && req.Method != "PUT" && req.Method != "HEAD" && req.Method != "OPTIONS" {
			s.debug.Println("Request contains unsupported Media Type:" + dataMime)
			return r.respond(415, "HTTP 415 - Unsupported Media Type:", dataMime)
		}
		req.ContentType = dataMime
	}

	// Content Negotiation
	contentType := constant.TextTurtle
	acceptList, _ := req.Accept()
	if len(acceptList) > 0 && acceptList[0].SubType != "*" {
		contentType, err = acceptList.Negotiate(mime.SerializerMimes...)
		if err != nil {
			s.debug.Println("Accept type not acceptable: " + err.Error())
			return r.respond(406, "HTTP 406 - Accept type not acceptable: "+err.Error())
		}
		req.AcceptType = contentType
	}

	// set ACL Link header
	w.Header().Set("Link", s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\", "+s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\"")

	// generic headers
	w.Header().Set("Accept-Patch", "application/json, application/sparql-update")
	w.Header().Set("Accept-Post", "text/turtle, application/json")
	w.Header().Set("Allow", strings.Join(constant.AllMethods(), ", "))
	w.Header().Set("Vary", "Origin")

	switch req.Method {
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
	case "COPY", "MOVE", "LOCK", "UNLOCK":
		s.CopyMoveLockUnlock(w, req, resource, acl)
	default:
		return r.respond(405, "405 - Method Not Allowed:", req.Method)
	}
	return
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
	err = json.Unmarshal(data, &v)
	if err != nil {
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
func (s *Server) ProxyReq(w http.ResponseWriter, req *httpRequest, reqUrl string) error {
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
			s.debug.Println(err.Error())
		}
		user, err := s.GetAuthzFromToken(token, req)
		if err != nil {
			s.debug.Println(err.Error())
		} else {
			s.debug.Println("HAuthorization valid for user", user)
		}
		req.User = user
	}

	if len(req.Header.Get(constant.HAuthorization)) > 0 {
		token, err := ParseBearerAuthorizationHeader(req.Header.Get(constant.HAuthorization))
		if err != nil {
			s.debug.Println(err.Error())
		}
		user, err := s.GetAuthzFromToken(token, req)
		if err != nil {
			s.debug.Println(err.Error())
		} else {
			s.debug.Println("HAuthorization valid for user", user)
		}
		req.User = user
	}

	req.URL = uri
	req.Host = uri.Host
	req.RequestURI = uri.RequestURI()
	req.Header.Set("User", req.User)
	proxy.ServeHTTP(w, req.Request)
	return nil
}
