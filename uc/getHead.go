package uc

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/err0r500/go-solid-server/constant"
	"github.com/err0r500/go-solid-server/domain"
	"github.com/err0r500/go-solid-server/mime"
)

func (s Server) GetHead(req RequestGetter, resource *domain.PathInfo, contentType string, acl WAC) *response {
	r := NewResponse()
	magicType := resource.FileType
	maybeRDF := false
	globPath := ""
	// etag := ""

	// check for glob
	glob := false
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
		r.HeaderSet(constant.HCType, contentType)
		urlStr := resource.URI
		s.logger.Debug("Redirecting to", urlStr)
		r.redirectURL = urlStr
		return r.respond(301)
	}

	// overwrite ACL Link header
	r.HeaderSet("Link", s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\", "+s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\"")

	// redirect to app
	if s.Config.Vhosts && !resource.Exists && resource.Base == strings.TrimRight(req.BaseURI(), "/") && contentType == constant.TextHtml && req.Method() != "HEAD" {
		r.HeaderSet(constant.HCType, contentType)
		r.redirectURL = s.Config.SignUpApp + url.QueryEscape(resource.Obj.Scheme+"://"+resource.Obj.Host+"/"+constant.SystemPrefix+"/accountStatus")
		return r.respond(303)
	}

	if resource.IsDir {
		r.HeaderAdd("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")
	}
	r.HeaderAdd("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

	status := 501
	aclStatus, err := s.AllowRead(acl, req.Header("Origin"), resource.URI)
	if aclStatus > 200 || err != nil {
		return r.respond(aclStatus, s.handleStatusText(aclStatus, err))
	}

	if req.Method() == "HEAD" {
		r.HeaderSet("Content-Length", fmt.Sprintf("%d", resource.Size))
	}

	etag, err := s.fileHandler.NewETag(resource.File)
	if err != nil {
		return r.respond(500, err)
	}
	r.HeaderSet("ETag", "\""+etag+"\"")

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
					r.HeaderSet("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
					break
				} else if req.Method() != "HEAD" {
					//TODO load file manager app from local preference file
					r.HeaderSet(constant.HCType, contentType)
					r.redirectURL = s.Config.DirApp + resource.Obj.Scheme + "/" + resource.Obj.Host + "/" + resource.Obj.Path + "?" + req.URLRawQuery()
					return r.respond(303)
				}
			}
		} else {
			r.HeaderAdd("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\"")

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
					r.HeaderSet("Preference-Applied", "return=representation")
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
			r.HeaderDel("ETag")
			r.HeaderSet("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
			if maybeRDF {
				r.HeaderSet(constant.HCType, contentType)
				return r.respond(200, s.templater.Login())
			}

			r.HeaderSet(constant.HCType, magicType)
			r.body, err = s.fileHandler.GetFileContent(resource.File)
			if err != nil {
				return r.respond(500, err.Error())
			}

			return r.respond(200)
		}
	}

	if status != 200 {
		return r.respond(status)
	}

	if req.Method() == "HEAD" {
		r.HeaderSet(constant.HCType, contentType)
		return r.respond(status)
	}

	if !maybeRDF && len(magicType) > 0 {
		r.HeaderSet(constant.HCType, magicType)
		if status != 200 {
			return r.respond(status)
		}

		r.body, err = s.fileHandler.GetFileContent(resource.File)
		if err != nil {
			return r.respond(500, err.Error())
		}

		return r.respond(200)
	}

	if maybeRDF {
		s.fileHandler.UpdateGraphFromFile(g, s.parser, resource.File)
		r.HeaderSet(constant.HCType, contentType)
	}

	data, err := s.parser.Serialize(g, contentType)
	if err != nil {
		return r.respond(500, err)
	}

	r.body = []byte(data)
	return r.respond(200)
}
