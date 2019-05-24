package main

import (
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
)

// nolint: gochecknoinits
func init() {
	// command line flags
	flag.StringVar(&cmdAddress, "address", "unix:/run/nginx-captcha.sock", `IP:PORT or Unix Socket path prefixd with "unix:"`)
	flag.BoolVar(&cmdLogDateTime, "log-date-time", true, "add date/time to log output")
	flag.BoolVar(&cmdDebug, "debug", false, "enable debug logging")
	flag.Parse()

	// define custom log flags
	var logFlag int
	if cmdLogDateTime {
		logFlag = log.Ldate | log.Ltime
	} else {
		logFlag = 0
	}
	// define debug log output
	var debugWriter io.Writer
	if cmdDebug {
		debugWriter = os.Stdout
		logFlag |= log.Lshortfile
	} else {
		debugWriter = ioutil.Discard
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
	Debug = log.New(
		debugWriter,
		"DEBUG: ",
		logFlag,
	)
}
