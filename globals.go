package main

import (
	"html/template"
	"sync"

	captcha "github.com/s3rj1k/captcha"
)

// nolint: gochecknoglobals
var (
	tmpl          *template.Template
	captchaConfig *captcha.Options

	db sync.Map
)
