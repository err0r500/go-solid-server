package gold

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/err0r500/go-solid-server/uc"
)

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
