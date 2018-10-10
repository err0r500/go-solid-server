package uc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/err0r500/go-solid-server/constant"
)

//func (s *Server) userCookieSet(w http.ResponseWriter, user string) error {
//	encoded, err := s.cookieManager.Encode("Session", map[string]string{"user": user})
//	if err != nil {
//		return err
//	}
//
//	cookieCfg := &http.Cookie{
//		Expires: time.Now().Add(time.Duration(s.Config.CookieAge) * time.Hour),
//		Name:    "Session",
//		Path:    "/",
//		Value:   encoded,
//		Secure:  true,
//	}
//
//	http.SetCookie(w, cookieCfg)
//	return nil
//}

//func (s *Server) userCookieDelete(w http.ResponseWriter) {
//	http.SetCookie(w, &http.Cookie{
//		Name:   "Session",
//		Value:  "deleted",
//		Path:   "/",
//		MaxAge: -1,
//	})
//}

// NewSecureToken generates a signed token to be used during account recovery
func (s Interactor) NewSecureToken(tokenType string, values map[string]string, duration time.Duration) (string, error) {
	values["valid"] = fmt.Sprintf("%d", time.Now().Add(duration).Unix())
	token, err := s.cookieManager.Encode(tokenType, values)
	if err != nil {
		s.logger.Debug("Error encoding new token: " + err.Error())
		return "", err
	}
	return token, nil
}

func IsTokenDateValid(valid string) error {
	v, err := strconv.ParseInt(valid, 10, 64)
	if err != nil {
		return err
	}

	if time.Now().Local().Unix() > v {
		return errors.New("token has expired")
	}

	return nil
}

func (s Interactor) GetAuthzFromToken(token string, user string, req SafeRequestGetter) (string, error) {
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
	return fmt.Sprintf("%x", sha256.Sum256([]byte(salt+pass)))
}

func encodeQuery(s string) string {
	return url.QueryEscape(s)
}
