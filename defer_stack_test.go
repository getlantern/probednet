package probednet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeferStack(t *testing.T) {
	t.Run("call order", func(t *testing.T) {
		callOrder := []int{}
		func() {
			s := new(deferStack)
			defer s.call()

			s.push(func() { callOrder = append(callOrder, 2) })
			s.push(func() { callOrder = append(callOrder, 1) })
			s.push(func() { callOrder = append(callOrder, 0) })
		}()
		require.Equal(t, 3, len(callOrder))
		for actualCallNumber, expectedCallNumber := range callOrder {
			assert.Equal(t, expectedCallNumber, actualCallNumber)
		}
	})

	t.Run("cancel", func(t *testing.T) {
		calls := 0
		func() {
			s := new(deferStack)
			defer s.call()

			s.push(func() { calls++ })
			s.push(func() { calls++ })
			s.push(func() { calls++ })
			s.cancel()
		}()
		assert.Equal(t, 0, calls)
	})
}
