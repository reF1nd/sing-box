package datastructure_test

import (
	"testing"

	"github.com/sagernet/sing-box/common/datastructure"
)

func TestGraphFindCircle(t *testing.T) {
	graph := datastructure.NewGraph[string, any]()
	a := datastructure.NewGraphNode[string, any]("a", nil)
	b := datastructure.NewGraphNode[string, any]("b", nil)
	c := datastructure.NewGraphNode[string, any]("c", nil)
	d := datastructure.NewGraphNode[string, any]("d", nil)
	e := datastructure.NewGraphNode[string, any]("e", nil)
	graph.AddNode(a)
	graph.AddNode(b)
	graph.AddNode(c)
	graph.AddNode(d)
	graph.AddNode(e)
	b.AddNext(a)
	c.AddNext(b)
	a.AddNext(e)
	d.AddNext(a)
	e.AddNext(c)
	circle := graph.FindCircle()
	t.Log(circle)
}
