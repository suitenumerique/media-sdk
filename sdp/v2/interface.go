package v2

type Clonable[T any] interface {
	Clone() T
}

type Builder[T any] interface {
	Build() (T, error)
}

type Buildable[T any, B Builder[T]] interface {
	Builder() B
}

type Marshallable interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}
