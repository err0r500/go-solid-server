package domain

import "strings"

type URIManipulator interface {
	Brack(s string) string
	Debrack(s string) string
	Defrag(s string) string
	Unquote(s string) string
}

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

// frag = lambda x: x[x.find('#')==-1 and len(x) or x.find('#'):len(x)-(x[-1]=='>')]
// unfrag = lambda x: '#' in x and (x[:x.find('#')==-1 and len(x) or x.find('#')] + (x[0]=='<' and '>' or '')) or x
// cpfrag = lambda x,y: unfrag(y)[-1] == '>' and unfrag(y)[:-1]+frag(x)+'>' or unfrag(y)+frag(x)
