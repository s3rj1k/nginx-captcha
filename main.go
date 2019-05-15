package main

import (
	"html/template"
	"net"
	"net/http"
	"os"
	"syscall"

	captcha "github.com/s3rj1k/captcha"
)

// ToDo:
//  - Add HTML JS page Refresh (?)
//  - Add graceful shutdown with CTRL+C (?)

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

	// remove old Unix socket
	if _, err = os.Stat(cmdSocket); !os.IsNotExist(err) {
		if err = syscall.Unlink(cmdSocket); err != nil {
			Error.Fatalf("captcha service socket error: %s\n", err.Error())
		}
	}

	// listen on unix socket
	us, err := net.Listen("unix", cmdSocket)
	if err != nil {
		Error.Fatalf("captcha service socket error: %s\n", err.Error())
	}

	// close unix socket on exit
	defer func() {
		if err = us.Close(); err != nil {
			Error.Fatalf("captcha service socket error: %s\n", err.Error())
		}
	}()

	// change unix socket permissions
	if err = os.Chmod(cmdSocket, os.FileMode(0777)); err != nil {
		Error.Fatalf("captcha service socket error: %s\n", err.Error())
	}

	// create new HTTP mux and define HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", captchaHandle)
	mux.HandleFunc("/auth", authHandle)

	// run DB cleaner to clean expired keys
	go cleanDB(&db)

	// start captcha server
	err = http.Serve(us, mux)
	if err != nil {
		Error.Fatalf("captcha service start error: %s\n", err.Error())
	}
}
