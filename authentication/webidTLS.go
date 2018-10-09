package authentication

import (
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/err0r500/go-solid-server/uc"

	"github.com/err0r500/go-solid-server/domain"
)

// WebIDTLSAuth - performs WebID-TLS authentication
func (s authenticator) WebIDTLSAuth(req uc.RequestGetter) (uri string, err error) {
	claim := ""
	uri = ""
	err = nil
	tls := req.TLS()

	if tls == nil || !tls.HandshakeComplete {
		return "", errors.New("Not a TLS connection. TLS handshake failed")
	}

	if len(tls.PeerCertificates) < 1 {
		return "", errors.New("No client certificate found in the TLS request!")
	}

	for _, x := range tls.PeerCertificates[0].Extensions {
		if !x.Id.Equal(subjectAltName) {
			continue
		}
		if len(x.Value) < 5 {
			continue
		}

		v := asn1.RawValue{}
		_, err = asn1.Unmarshal(x.Value, &v)
		if err == nil {
			san := ""
			for _, r := range string(v.Bytes[2:]) {
				if rune(r) == 65533 {
					san += ","
				} else if unicode.IsGraphic(rune(r)) {
					san += string(r)
				}
			}
			for _, sanURI := range strings.Split(san, ",") {
				sanURI = strings.TrimSpace(sanURI)
				if len(sanURI) == 0 {
					continue
				}
				if strings.HasPrefix(sanURI, "URI:") {
					claim = strings.TrimSpace(sanURI[4:])
					break
				} else if strings.HasPrefix(sanURI, "http") {
					claim = sanURI
					break
				}
			}
		}
		if len(claim) == 0 || claim[:4] != "http" {
			continue
		}

		pkey := tls.PeerCertificates[0].PublicKey
		t, n, e := pkeyTypeNE(pkey)
		if len(t) == 0 {
			continue
		}

		pkeyk := fmt.Sprint([]string{t, n, e})
		webidL.Lock()
		uri = pkeyURI[pkeyk]
		webidL.Unlock()
		if len(uri) > 0 {
			return
		}

		// pkey from client contains WebID claim

		g := domain.NewGraph(claim)
		err = s.httpCaller.LoadURI(g, claim)
		if err != nil {
			return "", err
		}

		for _, keyT := range g.All(domain.NewResource(claim), domain.NewNS("cert").Get("key"), nil) {
			// found pkey in the profile
			for range g.All(keyT.Object, domain.NewNS("rdf").Get("type"), domain.NewNS("cert").Get(t)) {
				for range g.All(keyT.Object, domain.NewNS("cert").Get("modulus"), domain.NewLiteral(n)) {
					goto matchModulus
				}
				for range g.All(keyT.Object, domain.NewNS("cert").Get("modulus"), domain.NewLiteralWithDatatype(n, domain.NewResource("http://www.w3.org/2001/XMLSchema#hexBinary"))) {
					goto matchModulus
				}
			matchModulus:
				// found a matching modulus in the profile
				for range g.All(keyT.Object, domain.NewNS("cert").Get("exponent"), domain.NewLiteral(e)) {
					goto matchExponent
				}
				for range g.All(keyT.Object, domain.NewNS("cert").Get("exponent"), domain.NewLiteralWithDatatype(e, domain.NewResource("http://www.w3.org/2001/XMLSchema#int"))) {
					goto matchExponent
				}
			matchExponent:
				// found a matching exponent in the profile
				//req.debug.Println("Found matching public modulus and exponent in user's profile")
				uri = claim
				webidL.Lock()
				pkeyURI[pkeyk] = uri
				webidL.Unlock()
				return
			}
			// could not find a certificate in the profile
		}
		// could not find a certificate pkey in the profile
	}
	return
}

func pkeyTypeNE(pkey interface{}) (t, n, e string) {
	switch pkey := pkey.(type) {
	//TODO: case *dsa.PublicKey
	case *rsa.PublicKey:
		t = "RSAPublicKey"
		n = fmt.Sprintf("%x", pkey.N)
		e = fmt.Sprintf("%d", pkey.E)
	}
	return
}
