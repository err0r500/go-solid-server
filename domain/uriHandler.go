package domain

import (
	"errors"
	"net/url"
	"strings"
)

type URIHandler struct{}

func (URIHandler) Brack(s string) string {
	if len(s) > 0 && s[0] == '<' {
		return s
	}
	if len(s) > 0 && s[len(s)-1] == '>' {
		return s
	}
	return "<" + s + ">"
}

func (URIHandler) Debrack(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] != '<' {
		return s
	}
	if s[len(s)-1] != '>' {
		return s
	}
	return s[1 : len(s)-1]
}

func (URIHandler) Defrag(s string) string {
	lst := strings.Split(s, "#")
	if len(lst) != 2 {
		return s
	}
	return lst[0]
}

func (URIHandler) Unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] != '"' {
		return s
	}
	if s[len(s)-1] != '"' {
		return s
	}
	return s[1 : len(s)-1]
}

func (URIHandler) ParseBearerAuthorizationHeader(header string) (string, error) {
	if len(header) == 0 {
		return "", errors.New("Cannot parse HAuthorization header: no header present")
	}

	parts := strings.SplitN(header, " ", 2)
	if parts[0] != "Bearer" {
		return "", errors.New("Not a Bearer header. Got: " + parts[0])
	}
	return decodeQuery(parts[1])
}

// fixme move to its own implementation folder
func decodeQuery(s string) (string, error) {
	return url.QueryUnescape(s)
}

// frag = lambda x: x[x.find('#')==-1 and len(x) or x.find('#'):len(x)-(x[-1]=='>')]
// unfrag = lambda x: '#' in x and (x[:x.find('#')==-1 and len(x) or x.find('#')] + (x[0]=='<' and '>' or '')) or x
// cpfrag = lambda x,y: unfrag(y)[-1] == '>' and unfrag(y)[:-1]+frag(x)+'>' or unfrag(y)+frag(x)
