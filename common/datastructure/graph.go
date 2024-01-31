package datastructure

type GraphNode[K comparable, T any] struct {
	id   K
	data T
	prev []*GraphNode[K, T]
	next []*GraphNode[K, T]
}

func NewGraphNode[K comparable, T any](id K, data T) *GraphNode[K, T] {
	return &GraphNode[K, T]{
		id:   id,
		data: data,
	}
}

func (n *GraphNode[K, T]) ID() K {
	return n.id
}

func (n *GraphNode[K, T]) Data() T {
	return n.data
}

func (n *GraphNode[K, T]) SetData(data T) {
	n.data = data
}

func (n *GraphNode[K, T]) Prev() []*GraphNode[K, T] {
	return n.prev
}

func (n *GraphNode[K, T]) Next() []*GraphNode[K, T] {
	return n.next
}

func (n *GraphNode[K, T]) AddPrev(prev *GraphNode[K, T]) {
	n.prev = append(n.prev, prev)
}

func (n *GraphNode[K, T]) AddNext(next *GraphNode[K, T]) {
	n.next = append(n.next, next)
}

func (n *GraphNode[K, T]) RemovePrev(prev *GraphNode[K, T]) {
	for i, p := range n.prev {
		if p == prev {
			n.prev = append(n.prev[:i], n.prev[i+1:]...)
			return
		}
	}
}

func (n *GraphNode[K, T]) RemoveNext(next *GraphNode[K, T]) {
	for i, p := range n.next {
		if p == next {
			n.next = append(n.next[:i], n.next[i+1:]...)
			return
		}
	}
}

func ToAnyNode[K comparable, T any](node *GraphNode[K, T]) *GraphNode[K, any] {
	return NewGraphNode[K, any](node.id, node.data)
}

type Graph[K comparable, T any] struct {
	nodes map[K]*GraphNode[K, T]
}

func NewGraph[K comparable, T any]() *Graph[K, T] {
	return &Graph[K, T]{
		nodes: make(map[K]*GraphNode[K, T]),
	}
}

func (g *Graph[K, T]) AddNode(node *GraphNode[K, T]) {
	g.nodes[node.id] = node
}

func (g *Graph[K, T]) GetNode(id K) *GraphNode[K, T] {
	return g.nodes[id]
}

func (g *Graph[K, T]) RemoveNode(id K) {
	delete(g.nodes, id)
}

func (g *Graph[K, T]) NodeMap() map[K]*GraphNode[K, T] {
	return g.nodes
}

func (g *Graph[K, T]) getPath(start, current K, stack map[K]bool) []K {
	var path []K
	for id := range stack {
		path = append(path, id)
		if id == current {
			break
		}
	}
	return path
}

func (g *Graph[K, T]) dfs(start, current K, visited, stack map[K]bool, result *[][]K) {
	visited[current] = true
	stack[current] = true
	node := g.nodes[current]
	for _, next := range node.next {
		if !visited[next.id] {
			g.dfs(start, next.id, visited, stack, result)
		} else if stack[next.id] && next.id == start {
			// Found a cycle, add the current path to the result
			path := g.getPath(start, current, stack)
			*result = append(*result, path)
		}
	}
	stack[current] = false
}

func (g *Graph[K, T]) FindCircle() [][]K {
	var (
		visited = make(map[K]bool)
		stack   = make(map[K]bool)
		result  [][]K
	)
	for id := range g.nodes {
		if !visited[id] {
			g.dfs(id, id, visited, stack, &result)
		}
	}
	return result
}
