package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"image/jpeg"
	"net"
	"net/http"
	"os"
	"syscall"
)

// <script src="https://code.jquery.com/jquery-1.10.2.js"></script>
// <script>
// 	$("#capthaForm").submit(function( event ) {
// 		event.preventDefault();
// 		var $form = $(this),
// 			answer = $form.find("input[id='answer']" ).val(),
// 			hash = $form.find("input[id='hash']" ).val(),
// 			url = $form.attr("action");
// 		var posting = $.post(url, {
// 			answer: answer,
// 			hash: hash,
// 		});
// 	});
// </script>

const captchaHTMLTemplate = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>CAPTCHA</title>
  </head>
  <style type='text/css'>
    .captcha {
	    width: 320px;
	  }
    #answer {
	    width: 200px;
    }
    #submit {
	    float: right;
	  }
	  #submit::after {
      clear: both;
    }
  </style>
	<body>
	  <div class="captcha">
      <img src="data:image/png;base64, {{ .Base64 }}" alt="{{ .Text }}" />
      <form id="#captchaForm" class="captcha" method="post" action="/solve">
	      <input type="hidden" id="hash" value="{{ .TextHash }}"> 
	      <input type="text" id="answer" value="">
		    <input type="button" id="submit" value="Submit">
			</form>
		</div>
  </body>
</html>
`

func hash(text string) string {
	return fmt.Sprintf("\t%x", sha512.Sum512_256([]byte(text)))
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
		TextHash: hash(captchaObj.Text),
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

func captchaSolveHandle(w http.ResponseWriter, _ *http.Request) {
}
