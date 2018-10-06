package cookies

import (
	"errors"

	"github.com/err0r500/go-solid-server/uc"
	"github.com/gorilla/securecookie"
)

type secureCookiesHandler struct {
	cookie *securecookie.SecureCookie
	salt   []byte
}

func New() uc.CookieManager {
	return secureCookiesHandler{
		cookie: securecookie.New(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32)),
		salt:   securecookie.GenerateRandomKey(8),
	}
}

func (c secureCookiesHandler) Encode(name string, value interface{}) (string, error) {
	return c.cookie.Encode(name, value)
}

func (c secureCookiesHandler) Decode(name, value string, dst interface{}) error {
	return c.cookie.Decode(name, value, dst)
}

func (c secureCookiesHandler) Check(token string) error {
	if token == string(c.salt) {
		return nil
	}

	return errors.New("wrong secret value in client token")
}
