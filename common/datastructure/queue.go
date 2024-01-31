package datastructure

type Queue[T any] struct {
	data []T
}

func NewQueue[T any]() *Queue[T] {
	return &Queue[T]{}
}

func (q *Queue[T]) Push(data T) {
	q.data = append(q.data, data)
}

func (q *Queue[T]) Pop() T {
	data := q.data[0]
	q.data = q.data[1:]
	return data
}

func (q *Queue[T]) Len() int {
	return len(q.data)
}

func (q *Queue[T]) Data() []T {
	return q.data
}
