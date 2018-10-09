package uc

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/err0r500/go-solid-server/constant"
	"github.com/err0r500/go-solid-server/domain"
)

func (s Interactor) Patch(req SafeRequestGetter, resource *domain.PathInfo, dataHasParser bool, dataMime string, acl WAC) (r *Response) {
	r = &Response{}

	// check append first
	aclAppend, err := s.AllowAppend(acl, req.Header("Origin"), resource.URI)
	if aclAppend > 200 || err != nil {
		// check if we can write then
		aclWrite, err := s.AllowWrite(acl, req.Header("Origin"), resource.URI)
		if aclWrite > 200 || err != nil {
			return r.Respond(aclWrite, s.handleStatusText(aclWrite, err))
		}
	}

	etag, _ := s.fileHandler.NewETag(resource.File)
	if !req.IfMatch("\"" + etag + "\"") {
		return r.Respond(412, "412 - Precondition Failed")
	}
	if !req.IfNoneMatch("\"" + etag + "\"") {
		return r.Respond(412, "412 - Precondition Failed")
	}

	if dataHasParser {
		s.logger.Debug("Preparing to PATCH resource", resource.URI, "with file", resource.File)
		buf, _ := ioutil.ReadAll(req.Body())
		body := ioutil.NopCloser(bytes.NewBuffer(buf))

		req.Body().Close()

		if req.Header("Content-Length") == "0" || len(buf) == 0 {
			errmsg := "Could not patch resource. No SPARQL statements found in the request."
			s.logger.Debug(errmsg)
			return r.Respond(400, errmsg)
		}

		g := domain.NewGraph(resource.URI)
		s.fileHandler.UpdateGraphFromFile(g, s.parser, resource.File)

		switch dataMime {
		case constant.ApplicationJSON:
			s.JSONPatch(g, body)
		case constant.ApplicationSPARQLUpdate:
			if ecode, err := s.sparqlHandler.SPARQLUpdate(g, body); err != nil {
				return r.Respond(ecode, "Error processing SPARQL Update: "+err.Error())
			}
		default:
			if dataHasParser {
				s.parser.Parse(g, body, dataMime)
			}
		}

		serializedGraph, err := s.parser.Serialize(g, constant.TextTurtle)
		if err != nil {
			return r.Respond(500, err)
		}
		if err := s.fileHandler.CreateOrUpdateFile(resource.File, strings.NewReader(serializedGraph)); err != nil {
			s.logger.Debug("PATCH g.SaveGraph err: " + err.Error())
			return r.Respond(500, err)
		}
		s.logger.Debug("succefully patched resource", resource.URI)
		//onUpdateURI(resource.URI)       //fixme ! (pass websocket handler behind an interface)
		//onUpdateURI(resource.ParentURI) //fixme !

		return r.Respond(200)
	}

	return r.Respond(500)
}

type jsonPatch map[string]map[string][]struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

// JSONPatch is used to perform a PATCH operation on a Graph using data from the reader
func (Interactor) JSONPatch(g *domain.Graph, r io.Reader) error {
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
