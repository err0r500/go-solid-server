package gold

import (
	"net"
	"net/http"
	"strings"

	"github.com/err0r500/go-solid-server/constant"
)

type httpRequest struct { // fixme attempt to make it purely abstract
	*http.Request

	AcceptType  string
	ContentType string
	User        string
	IsOwner     bool
	wac         WAC
}

func (req httpRequest) TargetsAPI() bool {
	return strings.Contains(req.Request.URL.Path, "/"+constant.SystemPrefix) && req.Method != "OPTIONS"
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
