package main

import (
	"bytes"
	"encoding/base64"
	"image/jpeg"
	"net/http"
	"time"
)

func renderHandle(w http.ResponseWriter, _ *http.Request) {
	// generate new captcha image
	captchaObj, err := captchaConfig.CreateImage()
	if err != nil {
		http.Error(w, "captcha failure", http.StatusInternalServerError)
	}

	var buff bytes.Buffer

	// encode captcha to JPEG
	err = jpeg.Encode(&buff, captchaObj.Image, nil)
	if err != nil {
		http.Error(w, "image encoder failure", http.StatusInternalServerError)
	}

	// populate struct with needed data for template render
	data := struct {
		Base64   string
		Text     string
		TextHash string
	}{
		// encode JPEG to base for data:URI
		Base64: base64.StdEncoding.EncodeToString(buff.Bytes()),
		// set captcha text
		Text: captchaObj.Text,
		// set captcha text hash
		TextHash: getStringHash(captchaObj.Text),
	}

	// generate expire date for captcha hash
	expires := time.Now().Add(time.Duration(captchaHashExpirationSeconds * 1000000000))

	// store captcha hash to db
	db.Store(data.TextHash, expires)

	// render captcha template
	err = captchaTemplate.Execute(w, data)
	if err != nil {
		http.Error(w, "HTML render failure", http.StatusInternalServerError)
	}
}
