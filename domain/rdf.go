package domain

//var (
//	ns = struct {
//		rdf, rdfs, acl, cert, foaf, stat, ldp, dct, space, st NS
//	}{
//		rdf:   NewNS("http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
//		rdfs:  NewNS("http://www.w3.org/2000/01/rdf-schema#"),
//		acl:   NewNS("http://www.w3.org/ns/auth/acl#"),
//		cert:  NewNS("http://www.w3.org/ns/auth/cert#"),
//		foaf:  NewNS("http://xmlns.com/foaf/0.1/"),
//		stat:  NewNS("http://www.w3.org/ns/posix/stat#"),
//		ldp:   NewNS("http://www.w3.org/ns/ldp#"),
//		dct:   NewNS("http://purl.org/dc/terms/"),
//		space: NewNS("http://www.w3.org/ns/pim/space#"),
//		st:    NewNS("http://www.w3.org/ns/solid/terms#"),
//	}
//)

// NS is a generic namespace type
type NS string

// NewNS is used to set a new namespace
func NewNS(base string) (ns NS) {
	return NS(base)
}

// Get is used to return the prefix for a namespace
func (ns NS) Get(name string) (term Term) {
	return NewResource(string(ns) + name)
}
