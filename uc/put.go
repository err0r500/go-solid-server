package uc

import (
	"github.com/err0r500/go-solid-server/domain"
)

func (s Interactor) Put(req RequestGetter, resource *domain.PathInfo, acl WAC) *Response {
	r := NewResponse()
	// LDP header
	r.HeaderAdd("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

	// check append first
	aclAppendStatus, err := s.AllowAppend(acl, req.Header("Origin"), resource.URI)
	if aclAppendStatus > 200 || err != nil {
		// check if we can write then
		aclWriteStatus, err := s.AllowWrite(acl, req.Header("Origin"), resource.URI)
		if aclWriteStatus > 200 || err != nil {
			return r.Respond(aclWriteStatus, s.handleStatusText(aclWriteStatus, err))
		}
	}

	etag, _ := s.fileHandler.NewETag(resource.File)
	if !req.IfMatch("\""+etag+"\"") || !req.IfNoneMatch("\""+etag+"\"") {
		return r.Respond(412, "412 - Precondition Failed")
	}

	isNew := true
	if resource.Exists {
		isNew = false
	}

	// LDP PUT should be merged with LDP POST into a common LDP "method" switch
	if ParseLinkHeader(req.Header("Link")).MatchRel("type") == "http://www.w3.org/ns/ldp#BasicContainer" {
		if err := s.fileHandler.CreateFileOrDir(resource.File); err != nil {
			return r.Respond(500, err)
		}

		// refresh resource and set the right headers
		newResource, err := s.pathInformer.GetPathInfo(resource.URI)
		if err != nil {
			return r.Respond(500, err)
		}
		r.HeaderSet("Link", s.uriManipulator.Brack(newResource.MetaURI)+"; rel=\"meta\", "+s.uriManipulator.Brack(newResource.AclURI)+"; rel=\"acl\"")
		// LDP header
		r.HeaderAdd("Link", s.uriManipulator.Brack("http://www.w3.org/ns/ldp#Resource")+"; rel=\"type\"")

		//onUpdateURI(newResource.URI)
		//onUpdateURI(newResource.ParentURI)
		return r.Respond(201)
	}

	if resource.IsDir {
		r.HeaderAdd("Link", s.uriManipulator.Brack(resource.URI)+"; rel=\"describedby\"")
		return r.Respond(406, "406 - Cannot use PUT on a directory.")
	}

	if err := s.fileHandler.CreateOrUpdateFile(resource.File, req.Body()); err != nil {
		return r.Respond(500, err)
	}

	r.HeaderSet("Location", resource.URI)

	//onUpdateURI(resource.URI) // fixme
	//onUpdateURI(resource.ParentURI)
	if isNew {
		return r.Respond(201)
	}
	return r.Respond(200)
}
