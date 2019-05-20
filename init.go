package main

import (
	"flag"
	"log"
	"os"
)

// nolint: gochecknoinits
func init() {
	// command line flags
	flag.StringVar(&cmdSocket, "socket", "/run/nginx-captcha.sock", "unix socket path")
	flag.Parse()

	// initialize loggers
	Info = log.New(
		os.Stdout,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)
	Error = log.New(
		os.Stderr,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile,
	)
}
