package probednet

type deferStack []func()

func (s *deferStack) call() {
	for i := len(*s) - 1; i >= 0; i-- {
		(*s)[i]()
	}
}

func (s *deferStack) push(f func()) {
	*s = append(*s, f)
}

func (s *deferStack) cancel() {
	*s = deferStack{}
}
