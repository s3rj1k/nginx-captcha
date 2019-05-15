package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/jpeg"
	"net/http"
	"strings"
	"time"
)

func captchaHandle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderHandle(w, r)
	case http.MethodPost:
		validateHandle(w, r)
	default:
		w.Header().Set("Allow", fmt.Sprintf("%s, %s", http.MethodGet, http.MethodPost))
		http.Error(w, "only GET or POST", http.StatusMethodNotAllowed)
	}
}

func renderHandle(w http.ResponseWriter, r *http.Request) {
	// allow only GET method
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "only GET", http.StatusMethodNotAllowed)
	}

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

func validateHandle(w http.ResponseWriter, r *http.Request) {
	// allow only POST method
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "only POST", http.StatusMethodNotAllowed)
	}

	// get captcha answer from request form, case insensitive
	answer := strings.ToUpper(strings.TrimSpace(r.PostFormValue("answer")))
	// get hidden captcha answer hash from request form
	hash := strings.TrimSpace(r.PostFormValue("hash"))

	// lookup captcha hash in db
	val, ok := db.Load(hash)
	if !ok {
		http.Error(w, "unknown captcha hash", http.StatusUnauthorized)
	}

	// check captcha hash expiration
	hashExpireTime, ok := val.(time.Time)
	if !ok {
		http.Error(w, "unknown captcha hash", http.StatusInternalServerError)
	}
	if hashExpireTime.Before(time.Now()) {
		http.Error(w, "expired captcha hash", http.StatusUnauthorized)
	}

	// validate user inputed captcha answer
	if getStringHash(answer) != hash {
		http.Error(w, "invalid captcha answer", http.StatusUnauthorized)
	}

	// generate ID for cookie value
	id, err := genUUID()
	if err != nil {
		http.Error(w, "entropy failure", http.StatusInternalServerError)
	}

	// generate expire date
	expires := time.Now().AddDate(0, 0, captchaCookieExpireDays)
	// create cookie
	cookie := &http.Cookie{
		Name:     captchaCookieName,
		Value:    id,
		Expires:  expires,
		MaxAge:   int(expires.Unix() - time.Now().Unix()),
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	// store cookie value to db
	db.Store(id, expires)
	// send cookie to client
	http.SetCookie(w, cookie)
}

func authHandle(w http.ResponseWriter, r *http.Request) {
	// get captcha cookie value from request
	if captchaCookie, err := r.Cookie(captchaCookieName); err == nil && captchaCookie != nil {
		// lookup cookie value in db
		if val, ok := db.Load(captchaCookie.Value); ok {
			// check cookie expiration
			if expireTime, ok := val.(time.Time); ok {
				if expireTime.After(time.Now()) {
					// cookie is valid
					return
				}
			}
		}
	}

	http.Error(w, "invalid captcha cookie", http.StatusUnauthorized)
}
