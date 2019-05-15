package main

import (
	"html/template"

	captcha "github.com/s3rj1k/captcha"
)

// nolint: gochecknoglobals
var (
	tmpl          *template.Template
	captchaConfig *captcha.Options
)
