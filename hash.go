package main

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2s"
)

// getStringHash creates hash as string from input string
func getStringHash(text ...string) string {
	b := []byte(strings.Join(text, ""))
	h := blake2s.Sum256(b)

	return fmt.Sprintf("%x", h)
}
