package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
)

// CreateRandom creates a []byte of the requested number of random values
func CreateRandom(size int) ([]byte, error) {
	values := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, values); err != nil {
		return nil, fmt.Errorf("Error creating random sequence: %s", err)
	}
	return values, nil
}
