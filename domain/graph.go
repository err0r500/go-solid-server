package domain

// Graph structure
type Graph struct {
	triples map[*Triple]bool
	uri     string
	term    Term
}

// NewGraph creates a Graph object
func NewGraph(uri string) *Graph {
	if uri[:5] != "http:" && uri[:6] != "https:" {
		panic(uri)
	}

	return &Graph{
		triples: make(map[*Triple]bool),
		uri:     uri,
		term:    NewResource(uri),
	}
}

// Len returns the length of the graph as number of triples in the graph
func (g *Graph) Len() int {
	return len(g.triples)
}

func (g *Graph) NotEmpty() bool {
	return len(g.triples) > 0
}

// Term returns a Graph Term object
func (g *Graph) Term() Term {
	return g.term
}

// URI returns a Graph URI object
func (g *Graph) URI() string {
	return g.uri
}

func isNilOrEquals(t1 Term, t2 Term) bool {
	if t1 == nil {
		return true
	}
	return t2.Equal(t1)
}

// One returns one triple based on a triple pattern of S, P, O objects
func (g *Graph) One(s Term, p Term, o Term) *Triple {
	for triple := range g.IterTriples() {
		if isNilOrEquals(s, triple.Subject) && isNilOrEquals(p, triple.Predicate) && isNilOrEquals(o, triple.Object) {
			return triple
		}
	}
	return nil
}

// IterTriples iterates through all the triples in a graph
func (g *Graph) IterTriples() (ch chan *Triple) {
	ch = make(chan *Triple)
	go func() {
		for triple := range g.triples {
			ch <- triple
		}
		close(ch)
	}()
	return ch
}

// Add is used to add a Triple object to the graph
func (g *Graph) Add(t *Triple) {
	g.triples[t] = true
}

// AddTriple is used to add a triple made of individual S, P, O objects
func (g *Graph) AddTriple(s Term, p Term, o Term) {
	g.triples[NewTriple(s, p, o)] = true
}

// Remove is used to remove a Triple object
func (g *Graph) Remove(t *Triple) {
	delete(g.triples, t)
}

// All is used to return all triples that match a given pattern of S, P, O objects
func (g *Graph) All(s Term, p Term, o Term) []*Triple {
	var triples []*Triple
	for triple := range g.IterTriples() {
		if s == nil && p == nil && o == nil {
			continue
		}
		if isNilOrEquals(s, triple.Subject) && isNilOrEquals(p, triple.Predicate) && isNilOrEquals(o, triple.Object) {
			triples = append(triples, triple)
		}
	}
	return triples
}
