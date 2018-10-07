package reqHandler

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/err0r500/go-solid-server/domain"

	"github.com/err0r500/go-solid-server/uc"

	"github.com/err0r500/go-solid-server/constant"
)

type httpRequest struct {
	request *http.Request
}

func NewSafeRequestGetter(rawReq *http.Request) uc.SafeRequestGetter {
	return httpRequest{
		request: rawReq,
	}
}

func NewRequestRawAccessor(rawReq *http.Request) uc.RequestRawAccessor {
	return httpRequest{
		request: rawReq,
	}
}

func NewRequestGetter(rawReq *http.Request) uc.RequestGetter {
	return httpRequest{
		request: rawReq,
	}
}

func (req httpRequest) Request() *http.Request {
	return req.request
}

func (req httpRequest) FormValue(key string) string {
	return req.request.FormValue(key)
}

func (req httpRequest) IsTLS() bool {
	return req.request.TLS != nil
}

func (req httpRequest) Method() string {
	return req.request.Method
}

func (req httpRequest) TLS() *tls.ConnectionState {
	return req.request.TLS
}

func (req httpRequest) CookieValue(key string) (string, error) {
	cookie, err := req.request.Cookie(key)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func (req httpRequest) Host() string {
	return req.request.Host
}

func (req httpRequest) TargetsAPI() bool {
	return strings.Contains(req.request.URL.Path, "/"+constant.SystemPrefix) && req.request.Method != "OPTIONS"
}

func (req httpRequest) BaseURI() string {
	scheme := "http"
	if req.request.TLS != nil || req.request.Header.Get("X-Forwarded-Proto") == "https" {
		scheme += "s"
	}
	reqHost := req.request.Host
	if len(req.Header("X-Forward-Host")) > 0 {
		reqHost = req.Header("X-Forward-Host")
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
	return scheme + "://" + host + port + req.request.URL.Path
}

func (req httpRequest) IfMatch(etag string) bool {
	if len(etag) == 0 {
		return true
	}
	if len(req.Header("If-Match")) == 0 {
		return true
	}

	val := strings.Split(req.Header("If-Match"), ",")
	for _, v := range val {
		v = strings.TrimSpace(v)
		if v == "*" || v == etag {
			return true
		}
	}
	return false
}

func (req httpRequest) IfNoneMatch(etag string) bool {
	if len(etag) == 0 {
		return true
	}
	if len(req.Header("If-None-Match")) == 0 {
		return true
	}
	val := strings.Split(req.Header("If-None-Match"), ",")
	for _, v := range val {
		v = strings.TrimSpace(v)
		if v != "*" && v != etag {
			return true
		}
	}
	return false
}

func (req httpRequest) Headers() map[string][]string       { return req.request.Header }
func (req httpRequest) URLRawQuery() string                { return req.request.URL.RawQuery }
func (req httpRequest) URLPath() string                    { return req.request.URL.Path }
func (req httpRequest) Header(key string) string           { return req.request.Header.Get(key) }
func (req httpRequest) HeaderComplete(key string) []string { return req.request.Header[key] }
func (req httpRequest) Body() io.ReadCloser                { return req.request.Body }
func (req httpRequest) MultipartFormContent() (map[string]io.Reader, error) {
	reader, err := req.request.MultipartReader()
	if err != nil {
		return nil, err
	}

	files := map[string]io.Reader{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}

		if part.FileName() == "" {
			continue
		}

		files[part.FileName()] = part
	}

	return files, nil
}

// Parse the Accept header and return a sorted list of clauses. If the Accept header
// is present but empty this will be an empty list. If the header is not present it will
// default to a wildcard: */*. Returns an error if the Accept header is ill-formed.
func (req httpRequest) Accept() (al domain.AcceptList, err error) {
	var accept string
	headers := req.HeaderComplete("Accept")
	if len(headers) > 0 {
		// if multiple Accept headers are specified just take the first one
		// such a client would be quite broken...
		accept = headers[0]
	} else {
		// default if not present
		accept = "*/*"
	}
	al, err = domain.ParseAccept(accept)
	return
}
