package mime

//
//import (
//	// "os"
//	"testing"
//
//	"github.com/stretchr/testify/assert"
//)
//
//var (
//	mimeParserExpect = map[string]string{
//		// constant.ApplicationJSON:          "internal",
//		"application/sparql-update": "internal",
//
//		"application/ld+json": "jsonld",
//		"application/rdf+xml": "rdfxml",
//		"application/rss":     "rss-tag-soup",
//		"application/x-trig":  "trig",
//		constant.TextN3:             "turtle",
//		constant.TextTurtle:         "turtle",
//		"text/x-nquads":       "nquads",
//		// "application/n-triples": "ntriples",
//	}
//	mimeSerializerExpect = map[string]string{
//		"application/ld+json": "internal",
//		constant.TextHtml:           "internal",
//
//		"application/atom+xml":  "atom",
//		constant.ApplicationJSON:      "json",
//		"application/rdf+xml":   "rdfxml-abbrev",
//		"application/rss+xml":   "rss-1.0",
//		"application/xhtml+xml": "html",
//		constant.TextTurtle:           "turtle",
//		"text/x-graphviz":       "dot",
//		"text/x-nquads":         "nquads",
//		// "application/n-triples": "ntriples",
//	}
//)
//
//func TestMimeParserExpect(t *testing.T) {
//	for k, v := range mimeParserExpect {
//		assert.Equal(t, v, MimeParser[k])
//	}
//}
//
//func TestMimeSerializerExpect(t *testing.T) {
//	for k, v := range mimeSerializerExpect {
//		assert.Equal(t, v, MimeSerializer[k])
//	}
//}
//
//func TestMapPathToExtension(t *testing.T) {
//	// empty	nil 	empty + error msg
//	path := ""
//	ctype := ""
//	res, err := MapPathToExtension(path, ctype)
//	assert.Error(t, err)
//	assert.Empty(t, res)
//
//	// /space/	nil 	/space/
//	path = "/space/"
//	ctype = ""
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Equal(t, path, res)
//
//	// /space/	text/html 	/space/
//	path = "/space/"
//	ctype = constant.TextHtml
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Equal(t, path, res)
//
//	// /space/foo	nil 	empty + error msg
//	path = "/space/foo"
//	ctype = ""
//	res, err = MapPathToExtension(path, ctype)
//	assert.Error(t, err)
//	assert.Empty(t, res)
//
//	// /space/foo.html	nil		/space/foo.html
//	path = "/space/foo.html"
//	ctype = ""
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Equal(t, path, res)
//
//	// /space/foo.html	text/html	/space/foo.html
//	path = "/space/foo.html"
//	ctype = constant.TextHtml
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Equal(t, path, res)
//
//	// /space/foo.ttl	nil		/space/foo.ttl
//	path = "/space/foo.ttl"
//	ctype = constant.TextTurtle
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Equal(t, path, res)
//
//	// /space/foo.html	text/turtle	/space/foo.html$.ttl
//	path = "/space/foo.html"
//	ctype = constant.TextTurtle
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Equal(t, path+"$.ttl", res)
//
//	// /space/foo	text/turtle	/space/foo.ttl
//	path = "/space/foo"
//	ctype = constant.TextTurtle
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Equal(t, path+".ttl", res)
//
//	// /space/foo.acl	text/turtle	/space/foo.acl
//	path = "/space/foo" + config.ACLSuffix
//	ctype = constant.TextTurtle
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Equal(t, path, res)
//
//	// /space/foo.meta	text/turtle	/space/foo.acl
//	path = "/space/foo" + config.MetaSuffix
//	ctype = constant.TextTurtle
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Equal(t, path, res)
//
//	// /space/foo	nil		/space/foo.jpg$.htm
//	path = "/space/foo"
//	ctype = constant.TextHtml
//	res, err = MapPathToExtension(path, "")
//	assert.Error(t, err)
//	assert.Empty(t, res)
//
//	// /space/foo.jpg	text/html	/space/foo.jpg$.htm
//	path = "/space/foo.jpg"
//	ctype = constant.TextHtml
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Contains(t, res, path+"$.htm")
//
//	// /space/foo.exe	text/html	/space/foo.exe$.htm
//	path = "/space/foo.exe"
//	ctype = constant.TextHtml
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Contains(t, res, path+"$.htm")
//
//	// /space/foo.ttl.acl	text/html	/space/foo.ttl.acl$.htm
//	path = "/space/foo.ttl" + config.ACLSuffix
//	ctype = constant.TextHtml
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Contains(t, res, path+"$.htm")
//
//	// /space/foo.b4r	text/html	/space/foo.b4r$.htm
//	path = "/space/foo.bar"
//	ctype = constant.TextHtml
//	res, err = MapPathToExtension(path, ctype)
//	assert.NoError(t, err)
//	assert.Contains(t, res, path+"$.htm")
//}
//
//func TestLookUpCtype(t *testing.T) {
//	cases := []struct {
//		in, want string
//	}{
//		{".ttl", constant.TextTurtle},
//		{".n3", constant.TextN3},
//		{".rdf", "application/rdf+xml"},
//		{".jsonld", "application/ld+json"},
//		{".unrecognized_ext", ""},
//	}
//	for _, c := range cases {
//		assert.Equal(t, c.want, LookUpCtype(c.in))
//	}
//}
