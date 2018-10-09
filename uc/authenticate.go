package uc

import (
	"github.com/err0r500/go-solid-server/constant"
)

func (s Interactor) Authenticate(req RequestGetter) string {
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
		user, err = s.authenticator.WebIDDigestAuth(req)
		if err != nil {
			//req.Server.debug.Println("WebID-RSA auth error:", err)
		}
		if len(user) > 0 {
			//req.Server.debug.Println("WebID-RSA auth OK for User: " + user)
		}
	}

	// fall back to WebID-TLS
	if len(user) == 0 {
		user, err = s.authenticator.WebIDTLSAuth(req)
		if err != nil {
			//req.Server.debug.Println("WebID-TLS error:", err)
		}
		if len(user) > 0 {
			//req.Server.debug.Println("WebID-TLS auth OK for User: " + user)
		}
	}

	return user
}

func (s Interactor) userCookie(req SafeRequestGetter) (string, error) {
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
