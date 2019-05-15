package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/jpeg"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

func captchaHandle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderHandle(w, r)
	case http.MethodPost:
		validateHandle(w, r)
	default:
		// set log data
		data := fmt.Sprintf("%d, only GET or POST method", http.StatusMethodNotAllowed)
		Error.Println(data)

		// return proper HTTP error with headers
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
		http.Error(w, data, http.StatusMethodNotAllowed)

		return
	}
}

func renderHandle(w http.ResponseWriter, r *http.Request) {
	// allow only GET method
	if r.Method != http.MethodGet {
		// set log data
		data := fmt.Sprintf("%d, only GET method", http.StatusMethodNotAllowed)
		Error.Println(data)

		// return proper HTTP error with headers
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, data, http.StatusMethodNotAllowed)

		return
	}

	// generate new captcha image
	captchaObj, err := captchaConfig.CreateImage()
	if err != nil {
		// set log data
		data := fmt.Sprintf("%d, captcha failure", http.StatusInternalServerError)
		Error.Println(data)

		// return proper HTTP error
		http.Error(w, data, http.StatusInternalServerError)

		return
	}

	var buff bytes.Buffer

	// encode captcha to JPEG
	err = jpeg.Encode(&buff, captchaObj.Image, nil)
	if err != nil {
		// set log data
		data := fmt.Sprintf("%d, image encoder failure", http.StatusInternalServerError)
		Error.Println(data)

		// return proper HTTP error
		http.Error(w, data, http.StatusInternalServerError)

		return
	}

	// populate struct with needed data for template render
	data := struct {
		Base64   string
		TextHash string
	}{
		// encode JPEG to base for data:URI
		Base64: base64.StdEncoding.EncodeToString(buff.Bytes()),
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
		// ignore buffer errors
		if nErr, ok := err.(*net.OpError); ok {
			if sysErr, ok := nErr.Err.(*os.SyscallError); ok {
				if sysErr.Err == syscall.EPIPE {
					return
				}
			}
		}

		// set log data
		data := fmt.Sprintf("%d, HTML render failure", http.StatusInternalServerError)
		Error.Println(data)

		// return proper HTTP error
		http.Error(w, data, http.StatusInternalServerError)

		return
	}
}

func validateHandle(w http.ResponseWriter, r *http.Request) {
	// allow only POST method
	if r.Method != http.MethodPost {
		// set log data
		data := fmt.Sprintf("%d, only POST method", http.StatusMethodNotAllowed)
		Error.Println(data)

		// return proper HTTP error with headers
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, data, http.StatusMethodNotAllowed)

		return
	}

	// get captcha answer from request form, case insensitive
	answer := strings.ToUpper(strings.TrimSpace(r.PostFormValue("answer")))
	// get hidden captcha answer hash from request form
	hash := strings.TrimSpace(r.PostFormValue("hash"))

	// lookup captcha hash in db
	val, ok := db.Load(hash)
	if !ok {
		// set log data
		data := fmt.Sprintf("%d, unknown captcha hash", http.StatusSeeOther)
		Info.Println(data)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)

		return
	}

	// check captcha hash expiration
	hashExpireTime, ok := val.(time.Time)
	if !ok {
		// set log data
		data := fmt.Sprintf("%d, unknown captcha hash", http.StatusInternalServerError)
		Info.Println(data)

		// return proper HTTP error
		http.Error(w, data, http.StatusInternalServerError)

		return
	}
	if hashExpireTime.Before(time.Now()) {
		// set log data
		data := fmt.Sprintf("%d, expired captcha hash", http.StatusSeeOther)
		Info.Println(data)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)

		return
	}

	// validate user inputed captcha answer
	if getStringHash(answer) != hash {
		// set log data
		data := fmt.Sprintf("%d, invalid captcha answer", http.StatusSeeOther)
		Info.Println(data)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)

		return
	}

	// generate ID for cookie value
	id, err := genUUID()
	if err != nil {
		// set log data
		data := fmt.Sprintf("%d, entropy failure", http.StatusInternalServerError)
		Error.Println(data)

		// return proper HTTP error
		http.Error(w, data, http.StatusInternalServerError)

		return
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

	// redirect to self
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func authHandle(w http.ResponseWriter, r *http.Request) {
	// get captcha cookie value from request
	if captchaCookie, err := r.Cookie(captchaCookieName); err == nil && captchaCookie != nil {
		// lookup cookie value in db
		if val, ok := db.Load(captchaCookie.Value); ok {
			// check cookie expiration
			if expireTime, ok := val.(time.Time); ok {
				if expireTime.After(time.Now()) {
					// set log data
					data := fmt.Sprintf("%d, valid captcha cookie", http.StatusOK)
					Info.Println(data)

					return // cookie is valid
				}
			}
		}
	}

	// set log data
	data := fmt.Sprintf("%d, invalid captcha cookie", http.StatusUnauthorized)
	Info.Println(data)

	// return proper HTTP error
	http.Error(w, data, http.StatusUnauthorized)
}
