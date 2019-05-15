package main

import (
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"regexp"
	"time"
)

// nolint: gochecknoinits
func init() {
	var err error

	// initialize global pseudo random generator
	rand.Seed(time.Now().Unix())

	// command line flags
	flag.StringVar(&cmdAddress, "address", "unix:/run/nginx-captcha.sock", `IP:PORT or Unix Socket path prefixd with "unix:"`)
	flag.StringVar(&cmdDBPath, "db", "/var/cache/nginx-captcha/captcha.db", `path to CAPTCHA database`)
	flag.UintVar(&cmdGenerate, "generate", 0, "specifies amount of unique CAPTHCAs to generate, zero has no action")
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
	Bot = log.New(
		os.Stdout,
		"BOT: ",
		logFlag,
	)

	// run generate CAPTCHA and exit
	if cmdGenerate > 0 {
		if err = generateCapcthaDB(cmdDBPath, cmdGenerate); err != nil {
			Error.Fatalf("regexp compile error: %s\n", err.Error())
		}

		os.Exit(0)
	}

	reUUID, err = regexp.Compile(regExpUUIDv4)
	if err != nil {
		Error.Fatalf("regexp compile error: %s\n", err.Error())
	}
}
