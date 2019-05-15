package main

import (
	"crypto/sha512"
	"fmt"
)

// getStringHash creates hash as string from input string
func getStringHash(text string) string {
	return fmt.Sprintf("%x", sha512.Sum512_256([]byte(text)))
}
