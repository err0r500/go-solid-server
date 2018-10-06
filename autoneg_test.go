// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gold

import (
	"net/http"
	"testing"

	"github.com/err0r500/go-solid-server/constant"
	"github.com/err0r500/go-solid-server/mime"
	"github.com/stretchr/testify/assert"
)

var (
	chrome = "application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
	rdflib = "application/rdf+xml;q=0.9, application/xhtml+xml;q=0.3, text/xml;q=0.2, application/xml;q=0.2, text/html;q=0.3, text/plain;q=0.1, text/n3;q=1.0, application/x-turtle;q=1, text/turtle;q=1"
)

func mockAccept(accept string) (al AcceptList, err error) {
	req := &http.Request{}
	req.Header = make(http.Header)
	req.Header["Accept"] = []string{accept}
	myreq := &httpRequest{req, "", "", "", false, WAC{}}
	al, err = myreq.Accept()
	return
}

func TestNegotiatePicturesOfWebPages(t *testing.T) {
	al, err := mockAccept(chrome)
	if err != nil {
		t.Fatal(err)
	}

	contentType, err := al.Negotiate(constant.TextHtml, "image/png")
	if err != nil {
		t.Fatal(err)
	}

	if contentType != "image/png" {
		t.Errorf("got %s expected image/png", contentType)
	}
}

func TestNegotiateRDF(t *testing.T) {
	al, err := mockAccept(rdflib)
	if err != nil {
		t.Fatal(err)
	}

	contentType, err := al.Negotiate(mime.SerializerMimes...)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "text/turtle", contentType)
}

func TestNegotiateFirstMatch(t *testing.T) {
	al, err := mockAccept(chrome)
	if err != nil {
		t.Fatal(err)
	}

	contentType, err := al.Negotiate(constant.TextHtml, constant.TextPlain, constant.TextN3)
	if err != nil {
		t.Fatal(err)
	}

	if contentType != constant.TextHtml {
		t.Errorf("got %s expected text/html", contentType)
	}
}

func TestNegotiateSecondMatch(t *testing.T) {
	al, err := mockAccept(chrome)
	if err != nil {
		t.Fatal(err)
	}

	contentType, err := al.Negotiate(constant.TextN3, constant.TextPlain)
	if err != nil {
		t.Fatal(err)
	}

	if contentType != constant.TextPlain {
		t.Errorf("got %s expected text/plain", contentType)
	}
}

func TestNegotiateWildcardMatch(t *testing.T) {
	al, err := mockAccept(chrome)
	if err != nil {
		t.Fatal(err)
	}

	contentType, err := al.Negotiate(constant.TextN3, "application/rdf+xml")
	if err != nil {
		t.Fatal(err)
	}

	if contentType != constant.TextN3 {
		t.Errorf("got %s expected text/n3", contentType)
	}
}

func TestNegotiateInvalidMediaRange(t *testing.T) {
	_, err := mockAccept("something/valid, rubbish, other/valid")
	if err == nil {
		t.Fatal("expected error on obviously invalid media range")
	}
}

func TestNegotiateInvalidParam(t *testing.T) {
	_, err := mockAccept("text/plain; foo")
	if err == nil {
		t.Fatal("expected error on ill-formed params")
	}
}

func TestNegotiateEmptyAccept(t *testing.T) {
	al, err := mockAccept("")
	if err != nil {
		t.Fatal(err)
	}

	_, err = al.Negotiate(constant.TextPlain)
	if err == nil {
		t.Error("expected error with empty but present accept header")
	}
}

func TestNegotiateStarAccept(t *testing.T) {
	al, err := mockAccept("*")
	if err != nil {
		t.Fatal(err)
	}
	if al[0].Type+"/"+al[0].SubType != "*/*" {
		t.Error("expected subtype * for single * accept header")
	}
}

func TestNegotiateNoAlternative(t *testing.T) {
	al, err := mockAccept(chrome)
	if err != nil {
		t.Fatal(err)
	}

	_, err = al.Negotiate()
	if err == nil {
		t.Error("expected error with no alternative")
	}
}
