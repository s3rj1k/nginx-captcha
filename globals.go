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
	listenAddress = "127.0.0.1:8080"
	// captcha cookie name
	captchaCookieName = "captcha"
	// number of days for captcha cookie expiration
	captchaCookieExpireDays = 1
	// number of seconds for captcha hash expiration
	captchaHashExpirationSeconds = 60
)

const captchaHTMLTemplate = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
		<title>CAPTCHA</title>
    <style type="text/css">
      .captcha {
	      width: 320px;
	    }
      .answerInput {
  	    width: 200px;
      }
      .submitButton {
	      float: right;
	    }
	    .submitButton::after {
        clear: both;
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
	  <div class="captcha">
      <img src="data:image/png;base64, {{ .Base64 }}" alt="{{ .Text }}" />
      <form id="#captchaForm" class="captcha" method="post" action="/validate">
	      <input type="hidden" name="hash" value="{{ .TextHash }}"> 
	      <input type="text" name="answer" class="answerInput" value="">
		    <input type="submit" class="submitButton" value="Verify">
			</form>
		</div>
  </body>
</html>
`
