package main

import (
	"html/template"
	"log"
	"sync"
	"time"

	captcha "github.com/s3rj1k/captcha"
)

const (
	// defines case-insensitive list of captcha characters.
	defaultCharsList = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// captcha cookie name
	captchaCookieName = "captcha"
	// number of seconds for captcha cookie expiration
	captchaCookieExpirationSeconds = 86400
	// number of seconds for captcha hash expiration
	captchaHashExpirationSeconds = 60
	// number of nanoseconds in second
	nanoSecondsInSecond = 1000000000
)

const (
	messageOnlyGetOrPostMethod  = "only GET or POST method"
	messageOnlyGetMethod        = "only GET method"
	messageOnlyPostMethod       = "only POST method"
	messageCaptchaFailure       = "captcha failure"
	messageImageEncoderFailure  = "image encoder failure"
	messageHTMLRenderFailure    = "HTML render failure"
	messageUnknownCaptchaHash   = "unknown captcha hash"
	messageExpiredCaptchaHash   = "expired captcha hash"
	messageInvalidCaptchaAnswer = "invalid captcha answer"
	messageEntropyFailure       = "entropy failure"
	messageValidCaptchaCookie   = "valid captcha cookie"
	messageInvalidCaptchaCookie = "invalid captcha cookie"
	messageInvalidCaptchaHash   = "invalid captcha hash"
	messageRecordExpired        = "record expired"
)

type captchaDBRecord struct {
	// Domain defines valid captcha domain
	Domain string
	// Expires defines captcha TTL
	Expires time.Time
}

// nolint: gochecknoglobals
var (
	// captcha HTML template
	captchaTemplate *template.Template
	// captcha config object
	captchaConfig *captcha.Options

	// in memory key:value db
	db sync.Map

	// unix socket path
	cmdSocket string
	// log date/time
	cmdLogDateTime bool

	// Logging levels
	Info  *log.Logger
	Error *log.Logger
)

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
    <script>
      $(document).ready(function() {
        $('#captcha').submit(function(event) {
          event.preventDefault();
          var xhr = new XMLHttpRequest();
          var data = new FormData(document.getElementById("captcha"));
          xhr.open('POST', '/', true);
          xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
          xhr.send(data);
        });
      });
    </script>
  </head>
  <body>
    <div class="container">
      <h2>CAPTCHA</h2>
      <p>Please verify that you are not a robot.</p>
      <img src="data:image/png;base64, {{ .Base64 }}" alt="{{ .TextHash }}" />
      <form id="#captcha" class="captcha" method="POST" action="/">
        <input type="hidden" name="hash" value="{{ .TextHash }}">
        <input type="text" name="answer" minlength="6" maxlength="6" pattern="[A-Za-z0-9]{6}" value="" autocomplete="off" autofocus>
        <button type="submit">VERIFY</button>
      </form>
    </div>
  </body>
</html>
`
