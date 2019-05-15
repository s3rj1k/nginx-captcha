package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"image/jpeg"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
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
      <form id="#captchaForm" class="captcha" method="post" action="/solve">
	      <input type="hidden" name="hash" value="{{ .TextHash }}"> 
	      <input type="text" name="answer" class="answerInput" value="">
		    <input type="submit" class="submitButton" value="Verify">
			</form>
		</div>
  </body>
</html>
`

func getStringHash(text string) string {
	return fmt.Sprintf("%x", sha512.Sum512_256([]byte(text)))
}

func captchaHandle(w http.ResponseWriter, _ *http.Request) {
	captchaObj, err := captchaConfig.CreateImage()
	if err != nil {
		http.Error(w, "captcha generation failed", http.StatusInternalServerError)
	}

	var buff bytes.Buffer

	err = jpeg.Encode(&buff, captchaObj.Image, nil)
	if err != nil {
		http.Error(w, "captcha image encoding failed", http.StatusInternalServerError)
	}

	data := struct {
		Base64   string
		Text     string
		TextHash string
	}{
		Base64:   base64.StdEncoding.EncodeToString(buff.Bytes()),
		Text:     captchaObj.Text,
		TextHash: getStringHash(captchaObj.Text),
	}

	if err = tmpl.Execute(w, data); err != nil {
		if nErr, ok := err.(*net.OpError); ok {
			if sysErr, ok := nErr.Err.(*os.SyscallError); ok {
				if sysErr.Err == syscall.EPIPE {
					return
				}
			}
		}

		http.Error(w, "captcha HTML render failed", http.StatusInternalServerError)
	}
}

func captchaSolveHandle(w http.ResponseWriter, r *http.Request) {
	answer := strings.ToUpper(strings.TrimSpace(r.PostFormValue("answer")))
	hash := strings.TrimSpace(r.PostFormValue("hash"))

	if getStringHash(answer) == hash {
		log.Println("GOOD BOY")
	} else {
		log.Println("BAD BOY")
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
