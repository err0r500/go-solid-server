package cookies

import (
	"errors"
	"net/http"
	"time"

	"github.com/err0r500/go-solid-server/uc"
	"github.com/gorilla/securecookie"
)

type secureCookiesHandler struct {
	cookie *securecookie.SecureCookie
	salt   []byte
	age    int64
}

func New(age int64) uc.CookieManager {
	return secureCookiesHandler{
		cookie: securecookie.New(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32)),
		salt:   securecookie.GenerateRandomKey(8),
		age:    age,
	}
}

func (c secureCookiesHandler) Encode(name string, value interface{}) (string, error) {
	return c.cookie.Encode(name, value)
}

func (c secureCookiesHandler) Decode(name, value string, dst interface{}) error {
	return c.cookie.Decode(name, value, dst)
}

// todo : is that normal, check this :
func (c secureCookiesHandler) Check(token string) error {
	if token == string(c.salt) {
		return nil
	}

	return errors.New("wrong secret value in client token")
}

func (c secureCookiesHandler) SetSessionCookie(w http.ResponseWriter, user string) error {
	encoded, err := c.Encode("Session", map[string]string{"user": user})
	if err != nil {
		return err
	}

	cookieCfg := &http.Cookie{
		Expires: time.Now().Add(time.Duration(c.age) * time.Hour),
		Name:    "Session",
		Path:    "/",
		Value:   encoded,
		Secure:  true,
	}

	http.SetCookie(w, cookieCfg)

	return nil
}

func (c secureCookiesHandler) DelSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "Session",
		Value:  "deleted",
		Path:   "/",
		MaxAge: -1,
	})
}
