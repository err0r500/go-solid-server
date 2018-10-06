package webdav

import (
	"net/http"

	"github.com/err0r500/go-solid-server/uc"
	"golang.org/x/net/webdav"
)

type webdavserver struct {
	handler *webdav.Handler
}

func New(dataRoot string) uc.WebDavHandler {
	return webdavserver{
		handler: &webdav.Handler{
			FileSystem: webdav.Dir(dataRoot),
			LockSystem: webdav.NewMemLS(),
		},
	}
}

func (s webdavserver) HandleReq(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}
