package main

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// genUUID - generates UUIDv4 (random), see: https://en.wikipedia.org/wiki/Universally_unique_identifier
func genUUID() string {
	u := make([]byte, 16)
	_, err := rand.Read(u)
	if err != nil {
		return "0d15ea5e-dead-dead-dead-defec8eddead"
	}

	// this make sure that the 13th character is "4"
	u[6] = (u[6] | 0x40) & 0x4F
	// this make sure that the 17th is "8", "9", "a", or "b"
	u[8] = (u[8] | 0x80) & 0xBF

	uuid := fmt.Sprintf("%X-%X-%X-%X-%X", u[0:4], u[4:6], u[6:8], u[8:10], u[10:])

	return strings.ToLower(uuid)
}
