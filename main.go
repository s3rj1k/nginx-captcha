package main

import (
	"html/template"
	"net/http"

	captcha "github.com/s3rj1k/captcha"
)

const defaultCharsList = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func main() {
	var err error

	captchaConfig, err = captcha.NewOptions()
	if err != nil {
		panic(err)
	}

	err = captchaConfig.SetCharacterList(defaultCharsList)
	if err != nil {
		panic(err)
	}

	err = captchaConfig.SetCaptchaTextLength(6)
	if err != nil {
		panic(err)
	}

	err = captchaConfig.SetDimensions(320, 100)
	if err != nil {
		panic(err)
	}

	tmpl, err = template.New("captcha.html").Parse(captchaHTMLTemplate)
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", captchaHandle)
	http.HandleFunc("/solve", captchaValidateHandle)

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}
