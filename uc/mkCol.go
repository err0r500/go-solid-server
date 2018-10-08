package uc

import (
	"github.com/err0r500/go-solid-server/domain"
)

func (s Server) MkCol(req SafeRequestGetter, resource *domain.PathInfo, acl WAC) *response {
	r := NewResponse()

	aclWrite, err := s.AllowWrite(acl, req.Header("Origin"), resource.URI)
	if aclWrite > 200 || err != nil {
		return r.respond(aclWrite, s.handleStatusText(aclWrite, err))
	}

	if err := s.fileHandler.CreateFileOrDir(resource.File); err != nil {
		return r.respond(409, err)
	}

	//onUpdateURI(resource.URI) ws interface
	//onUpdateURI(resource.ParentURI)
	return r.respond(201)
}
