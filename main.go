package main

import (
	"html/template"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"

	captcha "github.com/s3rj1k/captcha"
)

func main() {
	var err error

	// define default captcha config
	captchaConfig, err = captcha.NewOptions()
	if err != nil {
		Error.Fatalf("captcha service config error: %s\n", err.Error())
	}

	// set new captcha characters list
	err = captchaConfig.SetCharacterList(defaultCharsList)
	if err != nil {
		Error.Fatalf("captcha service config error: %s\n", err.Error())
	}

	// set captcha length
	err = captchaConfig.SetCaptchaTextLength(6)
	if err != nil {
		Error.Fatalf("captcha service config error: %s\n", err.Error())
	}

	// set captcha image size
	err = captchaConfig.SetDimensions(320, 100)
	if err != nil {
		Error.Fatalf("captcha service config error: %s\n", err.Error())
	}

	// prepare captcha HTML template
	captchaTemplate, err = template.New("captcha.html").Parse(captchaHTMLTemplate)
	if err != nil {
		Error.Fatalf("captcha service template error: %s\n", err.Error())
	}

	// create new HTTP mux and define HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", challengeHandle)
	mux.HandleFunc("/auth", authHandle)
	mux.HandleFunc("/favicon.ico", faviconHandler)

	// run DB cleaner to clean expired keys
	go cleanDB(&db)

	// define net listner for HTTP serve function
	var nl net.Listener

	switch {
	case strings.HasPrefix(cmdAddress, "unix:"):
		// get socket path
		socket := strings.TrimPrefix(cmdAddress, "unix:")

		// remove old Unix socket
		if _, err = os.Stat(socket); !os.IsNotExist(err) {
			if err = syscall.Unlink(socket); err != nil {
				Error.Fatalf("captcha service socket error: %s\n", err.Error())
			}
		}

		// listen on unix socket
		nl, err = net.Listen("unix", socket)
		if err != nil {
			Error.Fatalf("captcha service socket error: %s\n", err.Error())
		}

		// close unix socket on exit
		defer func() {
			if err = nl.Close(); err != nil {
				Error.Fatalf("captcha service socket error: %s\n", err.Error())
			}
		}()

		// change unix socket permissions
		if err = os.Chmod(socket, os.FileMode(0777)); err != nil {
			Error.Fatalf("captcha service socket error: %s\n", err.Error())
		}
	default:
		// listen on TCP
		nl, err = net.Listen("tcp", cmdAddress)
		if err != nil {
			Error.Fatalf("captcha service TCP error: %s\n", err.Error())
		}
	}

	// start captcha server
	err = http.Serve(nl, mux)
	if err != nil {
		Error.Fatalf("captcha service start error: %s\n", err.Error())
	}
}
