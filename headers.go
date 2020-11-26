package main

import (
	"net/http"
	"strings"
)

func isHTTPS(h http.Header) bool {
	return strings.EqualFold(h.Get("X-Scheme"), "https")
}
