package uc

import (
	"github.com/err0r500/go-solid-server/domain"
)

func (s Interactor) Delete(req SafeRequestGetter, resource *domain.PathInfo, acl WAC) *response {
	r := NewResponse()

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

	//onDeleteURI(resource.URI) fixme ws interface
	//onUpdateURI(resource.ParentURI)
	return r
}
