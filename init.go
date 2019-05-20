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
	flag.BoolVar(&cmdLogDateTime, "log-date-time", true, "add date/time to log output")
	flag.Parse()

	// define custom log flags
	var logFlag int
	if cmdLogDateTime {
		logFlag = log.Ldate | log.Ltime
	} else {
		logFlag = 0
	}

	// initialize loggers
	Info = log.New(
		os.Stdout,
		"INFO: ",
		logFlag,
	)
	Error = log.New(
		os.Stderr,
		"ERROR: ",
		logFlag,
	)
}
