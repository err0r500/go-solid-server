package gold

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/err0r500/go-solid-server/uc"

	"github.com/err0r500/go-solid-server/constant"
)

// DigestAuthentication structure
type DigestAuthentication struct {
	Type, Source, Username, Realm, Nonce, URI, QOP, NC, CNonce, Response, Opaque, Algorithm string
}

// DigestAuthorization structure
type DigestAuthorization struct {
	Type, Source, Username, Nonce, Signature string
}

func (s *Server) authn(req uc.RequestGetter, w http.ResponseWriter) string {
	user, err := s.userCookie(req)
	if err != nil {
		//req.Server.debug.Println("userCookie error:", err)
	}
	if len(user) > 0 {
		//req.Server.debug.Println("Cookie auth OK for User: " + user)
		return user
	}

	// try WebID-RSA
	if len(req.Header(constant.HAuthorization)) > 0 {
		user, err = s.WebIDDigestAuth(req)
		if err != nil {
			//req.Server.debug.Println("WebID-RSA auth error:", err)
		}
		if len(user) > 0 {
			//req.Server.debug.Println("WebID-RSA auth OK for User: " + user)
		}
	}

	// fall back to WebID-TLS
	if len(user) == 0 {
		user, err = s.WebIDTLSAuth(req.TLS())
		if err != nil {
			//req.Server.debug.Println("WebID-TLS error:", err)
		}
		if len(user) > 0 {
			//req.Server.debug.Println("WebID-TLS auth OK for User: " + user)
		}
	}

	if len(user) > 0 {
		if len(req.Header("On-Behalf-Of")) > 0 {
			delegator := s.uriManipulator.Debrack(req.Header("On-Behalf-Of"))
			if s.VerifyDelegator(delegator, user) {
				//req.Server.debug.Println("Setting delegation user to:", delegator)
				user = delegator
			}
		}
		s.userCookieSet(w, user)
		return user
	}

	user = ""
	//req.Server.debug.Println("Unauthenticated User")
	return user
}

func (s *Server) userCookie(req uc.SafeRequestGetter) (string, error) {
	cookieVal, err := req.CookieValue("Session")
	if err != nil {
		return "", err
	}

	value := make(map[string]string)
	if err := s.cookieManager.Decode("Session", cookieVal, &value); err != nil {
		return "", err
	}

	return value["user"], nil
}

func (s *Server) userCookieSet(w http.ResponseWriter, user string) error {
	value := map[string]string{
		"user": user,
	}

	encoded, err := s.cookieManager.Encode("Session", value)
	if err != nil {
		return err
	}
	t := time.Duration(s.Config.CookieAge) * time.Hour
	cookieCfg := &http.Cookie{
		Expires: time.Now().Add(t),
		Name:    "Session",
		Path:    "/",
		Value:   encoded,
		Secure:  true,
	}
	http.SetCookie(w, cookieCfg)
	return nil
}

func (s *Server) userCookieDelete(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "Session",
		Value:  "deleted",
		Path:   "/",
		MaxAge: -1,
	})
}

// ParseDigestAuthenticateHeader parses an Authenticate header and returns a DigestAuthentication object
func ParseDigestAuthenticateHeader(header string) (*DigestAuthentication, error) {
	auth := DigestAuthentication{}

	if len(header) == 0 {
		return &auth, errors.New("Cannot parse WWW-Authenticate header: no header present")
	}

	opts := make(map[string]string)
	parts := strings.SplitN(header, " ", 2)
	opts["type"] = parts[0]
	parts = strings.Split(parts[1], ",")

	for _, part := range parts {
		vals := strings.SplitN(strings.TrimSpace(part), "=", 2)
		key := vals[0]
		val := strings.Replace(vals[1], "\"", "", -1)
		opts[key] = val
	}

	auth = DigestAuthentication{
		opts["type"],
		opts["source"],
		opts["username"],
		opts["realm"],
		opts["nonce"],
		opts["uri"],
		opts["qop"],
		opts["nc"],
		opts["qnonce"],
		opts["response"],
		opts["opaque"],
		opts["algorithm"],
	}
	return &auth, nil
}

// ParseDigestAuthorizationHeader parses an HAuthorization header and returns a DigestAuthorization object
func ParseDigestAuthorizationHeader(header string) (*DigestAuthorization, error) {
	auth := DigestAuthorization{}

	if len(header) == 0 {
		return &auth, errors.New("Cannot parse HAuthorization header: no header present")
	}

	opts := make(map[string]string)
	parts := strings.SplitN(header, " ", 2)
	opts["type"] = parts[0]
	if opts["type"] == "Bearer" {
		return &auth, errors.New("Not a Digest authorization header. Got " + opts["type"])
	}

	parts = strings.Split(parts[1], ",")

	for _, part := range parts {
		vals := strings.SplitN(strings.TrimSpace(part), "=", 2)
		key := vals[0]
		val := strings.Replace(vals[1], "\"", "", -1)
		opts[key] = val
	}

	auth = DigestAuthorization{
		opts["type"],
		opts["source"],
		opts["username"],
		opts["nonce"],
		opts["sig"],
	}
	return &auth, nil
}

func ParseBearerAuthorizationHeader(header string) (string, error) {
	if len(header) == 0 {
		return "", errors.New("Cannot parse HAuthorization header: no header present")
	}

	parts := strings.SplitN(header, " ", 2)
	if parts[0] != "Bearer" {
		return "", errors.New("Not a Bearer header. Got: " + parts[0])
	}
	return decodeQuery(parts[1])
}

func NewTokenValues() map[string]string {
	return make(map[string]string)
}

// NewSecureToken generates a signed token to be used during account recovery
func (s *Server) NewSecureToken(tokenType string, values map[string]string, duration time.Duration) (string, error) {
	valid := time.Now().Add(duration).Unix()
	values["valid"] = fmt.Sprintf("%d", valid)
	token, err := s.cookieManager.Encode(tokenType, values)
	if err != nil {
		s.logger.Debug("Error encoding new token: " + err.Error())
		return "", err
	}
	return token, nil
}

// ValidateSecureToken returns the values of a secure cookie
func (s *Server) ValidateSecureToken(tokenType string, token string) (map[string]string, error) {
	values := make(map[string]string)
	err := s.cookieManager.Decode(tokenType, token, &values)
	if err != nil {
		s.logger.Debug("Secure token decoding error: " + err.Error())
		return values, err
	}

	return values, nil
}

func (s *Server) GetValuesFromToken(tokenType string, token string, req uc.SafeRequestGetter) (map[string]string, error) {
	values := NewTokenValues()
	token, err := decodeQuery(token)
	if err != nil {
		s.logger.Debug("Token URL decoding error for type: " + tokenType + " : " + err.Error())
		return values, err
	}
	err = s.cookieManager.Decode(tokenType, token, &values)
	if err != nil {
		s.logger.Debug("Token decoding error for type: " + tokenType + " \nToken: " + token + "\n" + err.Error())
		return values, err
	}
	return values, nil
}

func IsTokenDateValid(valid string) error {
	v, err := strconv.ParseInt(valid, 10, 64)
	if err != nil {
		return err
	}

	if time.Now().Local().Unix() > v {
		return errors.New("Token has expired!")
	}

	return nil
}

func (s *Server) GetAuthzFromToken(token string, user string, req uc.SafeRequestGetter) (string, error) {
	values, err := s.tokenStorer.GetPersistedToken(constant.HAuthorization, req.Host(), token)
	if err != nil {
		return "", err
	}
	if len(values["webid"]) == 0 && len(values["valid"]) == 0 &&
		len(values["origin"]) == 0 {
		return "", errors.New("Malformed token is missing required values")
	}

	err = IsTokenDateValid(values["valid"])
	if err != nil {
		return "", err
	}

	origin := req.Header("Origin")
	if len(origin) > 0 && origin != values["origin"] {
		return "", errors.New("Cannot authorize user: " + user + ". Origin: " + origin + " does not match the origin in the token: " + values["origin"])
	}
	return values["webid"], nil
}

func saltedPassword(salt, pass string) string {
	s := sha256.Sum256([]byte(salt + pass))
	toString := fmt.Sprintf("%x", s)
	return toString
}

func encodeQuery(s string) string {
	return url.QueryEscape(s)
}

func decodeQuery(s string) (string, error) {
	return url.QueryUnescape(s)
}
