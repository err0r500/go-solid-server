package authentication

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/err0r500/go-solid-server/constant"
	"github.com/err0r500/go-solid-server/domain"
	"github.com/err0r500/go-solid-server/uc"
)

// WebIDDigestAuth performs a digest authentication using WebID-RSA
func (s authenticator) WebIDDigestAuth(req uc.SafeRequestGetter) (string, error) {
	if len(req.Header(constant.HAuthorization)) == 0 {
		return "", nil
	}

	authH, err := ParseDigestAuthorizationHeader(req.Header(constant.HAuthorization))
	if err != nil {
		return "", err
	}

	if len(authH.Source) == 0 || authH.Source != req.BaseURI() {
		return "", errors.New("Bad source URI for auth token: " + authH.Source + " -- possible MITM attack!")
	}

	claim := sha1.Sum([]byte(authH.Source + authH.Username + authH.Nonce))
	signature, err := base64.StdEncoding.DecodeString(authH.Signature)
	if err != nil {
		return "", errors.New(err.Error() + " in " + authH.Signature)
	}

	if len(authH.Username) == 0 || len(claim) == 0 || len(signature) == 0 {
		return "", errors.New("No WebID and/or claim found in the HAuthorization header.\n" + req.Header(constant.HAuthorization))
	}

	// fetch WebID to get pubKey
	if !strings.HasPrefix(authH.Username, "http") {
		return "", errors.New("Username is not a valid HTTP URI: " + authH.Username)
	}

	// Decrypt and validate nonce from secure token
	tValues, err := s.ValidateSecureToken("WWW-Authenticate", authH.Nonce)
	if err != nil {
		return "", err
	}
	v, err := strconv.ParseInt(tValues["valid"], 10, 64)
	if err != nil {
		return "", err
	}
	if time.Now().Local().Unix() > v {
		return "", errors.New("Token expired for " + authH.Username)
	}
	if len(tValues["secret"]) == 0 {
		return "", errors.New("Missing secret from token (tempered with?)")
	}
	if err := s.cookieManager.Check(tValues["secret"]); err != nil {
		return "", err
	}

	g := domain.NewGraph(authH.Username)
	err = s.httpCaller.LoadURI(g, authH.Username)
	if err != nil {
		return "", err
	}

	//req.debug.Println("Checking for public keys for user", authH.Username)
	for _, keyT := range g.All(domain.NewResource(authH.Username), domain.NewNS("cert").Get("key"), nil) {
		for range g.All(keyT.Object, domain.NewNS("rdf").Get("type"), domain.NewNS("cert").Get("RSAPublicKey")) {
			//req.debug.Println("Found RSA key in user's profile", keyT.Object.String())
			for _, pubP := range g.All(keyT.Object, domain.NewNS("cert").Get("pem"), nil) {
				keyP := s.rdfHandler.FromDomain(pubP.Object).String()
				//req.debug.Println("Found matching public key in user's profile", keyP[:10], "...", keyP[len(keyP)-10:len(keyP)])
				parser, err := ParseRSAPublicPEMKey([]byte(keyP))
				if err == nil {
					err = parser.Verify(claim[:], signature)
					if err == nil {
						return authH.Username, nil
					}
				}
				//req.debug.Println("Unable to verify signature with key", keyP[:10], "...", keyP[len(keyP)-10:len(keyP)], "-- reason:", err)
			}
			// also loop through modulus/exp
			for _, pubN := range g.All(keyT.Object, domain.NewNS("cert").Get("modulus"), nil) {
				keyN := s.rdfHandler.FromDomain(pubN.Object).String()
				for _, pubE := range g.All(keyT.Object, domain.NewNS("cert").Get("exponent"), nil) {
					keyE := s.rdfHandler.FromDomain(pubE.Object).String()
					//req.debug.Println("Found matching modulus and exponent in user's profile", keyN[:10], "...", keyN[len(keyN)-10:len(keyN)])
					parser, err := ParseRSAPublicKeyNE("RSAPublicKey", keyN, keyE)
					if err == nil {
						err = parser.Verify(claim[:], signature)
						if err == nil {
							return authH.Username, nil
						}
					}
					//req.debug.Println("Unable to verify signature with key", keyN[:10], "...", keyN[len(keyN)-10:len(keyN)], "-- reason:", err)
				}
			}
		}
	}

	return "", err
}

// ValidateSecureToken returns the values of a secure cookie
func (s authenticator) ValidateSecureToken(tokenType string, token string) (map[string]string, error) {
	values := make(map[string]string)
	err := s.cookieManager.Decode(tokenType, token, &values)
	if err != nil {
		//s.logger.Debug("Secure token decoding error: " + err.Error())
		return values, err
	}

	return values, nil
}

// DigestAuthorization structure
type DigestAuthorization struct {
	Type, Source, Username, Nonce, Signature string
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

type rsaPubKey struct {
	*rsa.PublicKey
}

type rsaPrivKey struct {
	*rsa.PrivateKey
}

// ParseRSAPublicKeyNE parses a modulus and exponent and returns a new verifier object
func ParseRSAPublicKeyNE(keyT, keyN, keyE string) (uc.Verifier, error) {
	if len(keyN) == 0 && len(keyE) == 0 {
		return nil, errors.New("No modulus and/or exponent provided")
	}
	intN := new(big.Int)
	intN.SetString(keyN, 16)

	intE, err := strconv.ParseInt(keyE, 10, 0)
	if err != nil {
		return nil, err
	}

	var rawkey interface{}
	switch keyT {
	case "RSAPublicKey":
		rawkey = &rsa.PublicKey{
			N: intN,
			E: int(intE),
		}
	default:
		return nil, fmt.Errorf("Unsupported key type %q", keyT)
	}
	return newVerifierFromKey(rawkey)
}

// ParseRSAPublicKey parses an RSA public key and returns a new verifier object
func ParseRSAPublicKey(key *rsa.PublicKey) (uc.Verifier, error) {
	return newVerifierFromKey(key)
}

// ParseRSAPrivateKey parses an RSA private key and returns a new signer object
func ParseRSAPrivateKey(key *rsa.PrivateKey) (uc.Signer, error) {
	return newSignerFromKey(key)
}

// ParseRSAPublicPEMKey parses a PEM encoded private key and returns a new verifier object
func ParseRSAPublicPEMKey(pemBytes []byte) (uc.Verifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("No key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PUBLIC KEY", "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("Unsupported key type %q", block.Type)
	}

	return newVerifierFromKey(rawkey)
}

// ParseRSAPrivatePEMKey parses a PEM encoded private key and returns a Signer.
func ParseRSAPrivatePEMKey(pemBytes []byte) (uc.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("No key found or could not decode PEM key")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY", "PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("Unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

func newSignerFromKey(k interface{}) (uc.Signer, error) {
	var sKey uc.Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sKey = &rsaPrivKey{t}
	default:
		return nil, fmt.Errorf("Unsupported key type %T", k)
	}
	return sKey, nil
}

func newVerifierFromKey(k interface{}) (uc.Verifier, error) {
	var vKey uc.Verifier
	switch t := k.(type) {
	case *rsa.PublicKey:
		vKey = &rsaPubKey{t}
	default:
		return nil, fmt.Errorf("Unsupported key type %T", k)
	}
	return vKey, nil
}

// Sign signs data with rsa-sha256
func (r *rsaPrivKey) Sign(data []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA1, data)
}

// Verify verifies the message using a rsa-sha256 signature
func (r *rsaPubKey) Verify(message []byte, sig []byte) error {
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA1, message, sig)
}
