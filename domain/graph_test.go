package domain_test

import (
	"testing"

	"github.com/err0r500/go-solid-server/domain"
	"github.com/stretchr/testify/assert"
)

func TestGraphOne(t *testing.T) {
	g := domain.NewGraph("http://test/")

	g.AddTriple(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("c"))
	assert.Equal(t, g.One(domain.NewResource("a"), nil, nil).String(), "<a> <b> <c> .")
	assert.Equal(t, g.One(domain.NewResource("a"), domain.NewResource("b"), nil).String(), "<a> <b> <c> .")

	g.AddTriple(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("d"))
	assert.Equal(t, g.One(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("d")).String(), "<a> <b> <d> .")
	assert.Equal(t, g.One(nil, domain.NewResource("b"), domain.NewResource("d")).String(), "<a> <b> <d> .")

	g.AddTriple(domain.NewResource("g"), domain.NewResource("b2"), domain.NewLiteral("e"))
	assert.Equal(t, g.One(nil, domain.NewResource("b2"), nil).String(), "<g> <b2> \"e\" .")
	assert.Equal(t, g.One(nil, nil, domain.NewLiteral("e")).String(), "<g> <b2> \"e\" .")

	assert.Nil(t, g.One(domain.NewResource("x"), nil, nil))
	assert.Nil(t, g.One(nil, domain.NewResource("x"), nil))
	assert.Nil(t, g.One(nil, nil, domain.NewResource("x")))
}

func TestGraphAll(t *testing.T) {
	g := domain.NewGraph("http://test/")
	g.AddTriple(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("c"))
	g.AddTriple(domain.NewResource("a"), domain.NewResource("b"), domain.NewResource("d"))
	g.AddTriple(domain.NewResource("a"), domain.NewResource("f"), domain.NewLiteral("h"))
	g.AddTriple(domain.NewResource("g"), domain.NewResource("b2"), domain.NewResource("e"))
	g.AddTriple(domain.NewResource("g"), domain.NewResource("b2"), domain.NewResource("c"))

	assert.Equal(t, 0, len(g.All(nil, nil, nil)))
	assert.Equal(t, 3, len(g.All(domain.NewResource("a"), nil, nil)))
	assert.Equal(t, 2, len(g.All(nil, domain.NewResource("b"), nil)))
	assert.Equal(t, 1, len(g.All(nil, nil, domain.NewResource("d"))))
	assert.Equal(t, 2, len(g.All(nil, nil, domain.NewResource("c"))))
}
