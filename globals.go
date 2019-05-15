package main

import (
	"html/template"
	"sync"

	captcha "github.com/s3rj1k/captcha"
)

// nolint: gochecknoglobals
var (
	// captcha HTML template
	captchaTemplate *template.Template
	// captcha config object
	captchaConfig *captcha.Options
	// in memory key:value db
	db sync.Map
)

const (
	// HTTP server listen address
	listenAddress = "127.0.0.1:7169"

	// defines case-insensitive list of captcha characters.
	defaultCharsList = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// captcha cookie name
	captchaCookieName = "captcha"
	// number of days for captcha cookie expiration
	captchaCookieExpireDays = 1
	// number of seconds for captcha hash expiration
	captchaHashExpirationSeconds = 60
)

// https://www.w3schools.com/howto/howto_css_search_button.asp

const captchaHTMLTemplate = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" name="viewport" content="width=device-width, initial-scale=1">
    <title>CAPTCHA</title>
    <style>
      * {
        box-sizing: border-box;
      }
      input[type="text"] {
        text-align: center;
      }
    </style>
    <script src="https://code.jquery.com/jquery-1.10.2.js"></script>
    <script>
      $(document).ready(function() {
        $('#captchaForm').submit(function(event) {
          event.preventDefault();
            $.ajax({
              url: $(this).attr("action"),
              type: $(this).attr("method"),
              data: $(this).serialize()
            });
        });
      });
    </script>
  </head>
  <body>
    <div class="container">
      <h2>CAPTCHA</h2>
      <img src="data:image/png;base64, {{ .Base64 }}" alt="{{ .Text }}" />
      <form id="#captchaForm" method="POST" action="/">
        <input type="hidden" name="hash" value="{{ .TextHash }}">
        <input type="text" name="answer" minlength="6" maxlength="6" pattern="[A-Za-z0-9]{6}" value="">
        <input type="submit" formtarget="_self" value="Verify">
      </form>
    </div>
  </body>
</html>
`
