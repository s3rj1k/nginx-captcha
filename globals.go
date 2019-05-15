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
      .container {
        margin: auto;
        max-width: 320px;
      }
      .container h2 {
        text-align: center;
      }
      form.captcha input[type="text"] {
        text-align: center;
        padding: 10px;
        font-size: 17px;
        border: 1px solid grey;
        float: left;
        width: 74%;
        background: #f1f1f1;
      }
      form.captcha button {
        float: left;
        width: 26%;
        padding: 10px;
        background: #2196F3;
        color: white;
        font-size: 17px;
        border: 1px solid grey;
        border-left: none;
        cursor: pointer;
      }
      form.captcha button:hover {
        background: #0b7dda;
      }
      form.captcha::after {
        content: "";
        clear: both;
        display: table;
      }
    </style>
    <script src="https://code.jquery.com/jquery-1.10.2.js"></script>
    <script>
      $(document).ready(function() {
        $('#captcha').submit(function(event) {
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
      <img src="data:image/png;base64, {{ .Base64 }}" alt="{{ .TextHash }}" />
      <form id="#captcha" class="captcha" method="POST" action="/">
        <input type="hidden" name="hash" value="{{ .TextHash }}">
        <input type="text" name="answer" minlength="6" maxlength="6" pattern="[A-Za-z0-9]{6}" value="">
        <button type="submit">VERIFY</button>
      </form>
    </div>
  </body>
</html>
`
