package main

import (
	"html/template"
	"net/http"

	captcha "github.com/s3rj1k/captcha"
)

// defaultCharsList defines case-insensitive list of captcha characters.
const defaultCharsList = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func main() {
	var err error

	// define default captcha config
	captchaConfig, err = captcha.NewOptions()
	if err != nil {
		panic(err)
	}

	// set new captcha characters list
	err = captchaConfig.SetCharacterList(defaultCharsList)
	if err != nil {
		panic(err)
	}

	// set captcha length
	err = captchaConfig.SetCaptchaTextLength(6)
	if err != nil {
		panic(err)
	}

	// set captcha image size
	err = captchaConfig.SetDimensions(320, 100)
	if err != nil {
		panic(err)
	}

	// prepare captcha HTML template
	captchaTemplate, err = template.New("captcha.html").Parse(captchaHTMLTemplate)
	if err != nil {
		panic(err)
	}

	// define HTTP routes
	http.HandleFunc("/", renderHandle)
	http.HandleFunc("/auth", authHandle)
	http.HandleFunc("/validate", validateHandle)

	// start captcha server
	err = http.ListenAndServe(listenAddress, nil)
	if err != nil {
		panic(err)
	}
}
