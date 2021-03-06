package uc

import (
	"io"
	"log"
	"net/url"
	"strings"

	"github.com/err0r500/go-solid-server/constant"
	"github.com/err0r500/go-solid-server/domain"
)

func (s Interactor) Post(req SafeRequestGetter, resource *domain.PathInfo, dataHasParser bool, dataMime string, acl WAC) *Response {
	r := NewResponse()

	// check append first
	aclAppend, err := s.CheckAllow(acl, appendAccess, req.Header("Origin"), resource.URI)
	if aclAppend > 200 || err != nil {
		// check if we can write then
		aclWrite, err := s.CheckAllow(acl, writeAccess, req.Header("Origin"), resource.URI)
		if aclWrite > 200 || err != nil {
			return r.Respond(aclWrite, s.handleStatusText(aclWrite, err))
		}
	}
	err = nil

	etag, _ := s.fileHandler.NewETag(resource.File)
	if !req.IfMatch("\"" + etag + "\"") {
		return r.Respond(412, "412 - Precondition Failed")
	}
	if !req.IfNoneMatch("\"" + etag + "\"") {
		return r.Respond(412, "412 - Precondition Failed")
	}

	// LDP
	isNew := false
	if resource.IsDir && dataMime != constant.MultipartFormData {
		link := ParseLinkHeader(req.Header("Link")).MatchRel("type")
		slug := req.Header("Slug")
		uuid := s.uuidGenerator.UUID()

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
				return r.Respond(500, err)
			}

			r.HeaderSet("Location", resource.URI)
			r.HeaderSet("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
			r.HeaderAdd("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")
			r.HeaderAdd("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#BasicContainer")+"; rel=\"type\"")

			if err := s.fileHandler.SaveFiles(resource.File, map[string]io.Reader{resource.MetaFile: req.Body()}); err != nil {
				return r.Respond(500, err)
			}
			s.logger.Debug("Created dir " + resource.File)

			r.HeaderSet("Location", resource.URI)
			//onUpdateURI(resource.URI) // fixme, needs websocketInterface
			//onUpdateURI(resource.ParentURI)
			return r.Respond(201)
		}

		resource, err = s.pathInformer.GetPathInfo(resource.Base + "/" + resource.Path)
		if err != nil {
			s.logger.Debug("POST LDPR req.pathInfo err: " + err.Error())
			return r.Respond(500, err)
		}
		r.HeaderSet("Location", resource.URI)
		r.HeaderSet("Link", s.uriManipulator.Brack(resource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(resource.AclURI)+"; rel=\"acl\"")
		// LDP header
		r.HeaderAdd("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")
		isNew = true
	}

	if dataMime == constant.MultipartFormData {
		toStore, err := req.MultipartFormContent()
		if err != nil {
			return r.Respond(500, err)
		}

		for filename, _ := range toStore {
			location := &url.URL{Path: filename}
			r.HeaderAdd("Location", resource.URI+location.String())
		}

		if err := s.fileHandler.SaveFiles(resource.File, toStore); err != nil {
			return r.Respond(500, err)
		}

		//onUpdateURI(resource.URI)// needs websocket interface
		return r.Respond(201)
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
					return r.Respond(400, "failed to handle JSONPatch request")
				}
			case constant.ApplicationSPARQLUpdate:
				if ecode, err := s.sparqlHandler.SPARQLUpdate(g, req.Body()); err != nil {
					return r.Respond(ecode, "Error processing SPARQL Update: "+err.Error())
				}
			default:
				s.parser.Parse(g, req.Body(), dataMime)
			}

			if err := s.fileHandler.CreateFileOrDir(resource.File); err != nil {
				return r.Respond(500, err.Error())
			}

			if g.NotEmpty() {
				serializedGraph, err := s.parser.Serialize(g, constant.TextTurtle)
				if err != nil {
					return r.Respond(500, err)
				}
				if err := s.fileHandler.CreateOrUpdateFile(resource.File, strings.NewReader(serializedGraph)); err != nil {
					s.logger.Debug("POST g.SaveGraph err: " + err.Error())
				} else {
					s.logger.Debug("Wrote resource file: " + resource.File)
				}
			}
		} else {
			log.Println("==>>")
			if err := s.fileHandler.SaveFiles(resource.File, map[string]io.Reader{resource.File: req.Body()}); err != nil {
				return r.Respond(500, err.Error())
			}
		}

		//onUpdateURI(resource.URI) // fixme needs ws interface
		if resource.URI != resource.ParentURI {
			//onUpdateURI(resource.ParentURI)
		}
		if isNew {
			return r.Respond(201)
		}
		return r.Respond(200)
	}

	return r.Respond(500)
}
