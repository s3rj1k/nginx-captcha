package main

import (
	"bytes"
	"encoding/base64"
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
		Info.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusMethodNotAllowed,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageOnlyGetOrPostMethod,
		)

		// return proper HTTP error with headers
		w.Header().Set(
			"Allow",
			strings.Join(
				[]string{
					http.MethodGet,
					http.MethodPost,
				}, ", ",
			),
		)
		http.Error(w, messageOnlyGetOrPostMethod, http.StatusMethodNotAllowed)
		return
	}
}

func renderHandle(w http.ResponseWriter, r *http.Request) {
	// allow only GET method
	if r.Method != http.MethodGet {
		Info.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusMethodNotAllowed,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageOnlyGetMethod,
		)

		// return proper HTTP error with headers
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, messageOnlyGetMethod, http.StatusMethodNotAllowed)
		return
	}

	// generate new captcha image
	captchaObj, err := captchaConfig.CreateImage()
	if err != nil {
		Error.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageCaptchaFailure,
		)

		// return proper HTTP error
		http.Error(w, messageCaptchaFailure, http.StatusInternalServerError)
		return
	}

	var buff bytes.Buffer

	// encode captcha to JPEG
	err = jpeg.Encode(&buff, captchaObj.Image, nil)
	if err != nil {
		Error.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageImageEncoderFailure,
		)

		// return proper HTTP error
		http.Error(w, messageImageEncoderFailure, http.StatusInternalServerError)
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
	expires := time.Now().Add(time.Duration(captchaHashExpirationSeconds * nanoSecondsInSecond))

	// store captcha hash to db
	db.Store(data.TextHash,
		captchaDBRecord{
			Domain:  r.Header.Get("X-Forwarded-Host"),
			Expires: expires,
		},
	)

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

		Error.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageHTMLRenderFailure,
		)

		// return proper HTTP error
		http.Error(w, messageHTMLRenderFailure, http.StatusInternalServerError)
		return
	}
}

func validateHandle(w http.ResponseWriter, r *http.Request) {
	// allow only POST method
	if r.Method != http.MethodPost {
		Info.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusMethodNotAllowed,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageOnlyPostMethod,
		)

		// return proper HTTP error with headers
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, messageOnlyPostMethod, http.StatusMethodNotAllowed)
		return
	}

	// get captcha answer from request form, case insensitive
	answer := strings.ToUpper(strings.TrimSpace(r.PostFormValue("answer")))
	// get hidden captcha answer hash from request form
	hash := strings.TrimSpace(r.PostFormValue("hash"))

	// lookup captcha hash in db
	val, ok := db.Load(hash)
	if !ok {
		Info.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageUnknownCaptchaHash,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// check captcha hash record
	record, ok := val.(captchaDBRecord)
	if !ok {
		Error.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageUnknownCaptchaHash,
		)

		// return proper HTTP error
		http.Error(w, messageUnknownCaptchaHash, http.StatusInternalServerError)
		return
	}

	// check that captcha hash is valid for domain
	if !strings.EqualFold(r.Header.Get("X-Forwarded-Host"), record.Domain) {
		Info.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageInvalidCaptchaHash,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// check captcha hash expiration
	if record.Expires.Before(time.Now()) {
		Info.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageExpiredCaptchaHash,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// validate user inputed captcha answer
	if getStringHash(answer) != hash {
		Info.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageInvalidCaptchaAnswer,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// generate ID for cookie value
	id, err := genUUID()
	if err != nil {
		Error.Printf(
			"%d, URL:%s%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Forwarded-Host"),
			r.URL,
			messageEntropyFailure,
		)

		// return proper HTTP error
		http.Error(w, messageEntropyFailure, http.StatusInternalServerError)
		return
	}

	// generate expire for cookie
	expires := time.Now().Add(time.Duration(captchaCookieExpirationSeconds * nanoSecondsInSecond))

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

	// store captcha hash to db
	db.Store(id,
		captchaDBRecord{
			Domain:  r.Header.Get("X-Forwarded-Host"),
			Expires: expires,
		},
	)

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
			// check captcha hash record
			if record, ok := val.(captchaDBRecord); ok {
				// check that cookie is valid for domain
				if strings.EqualFold(r.Header.Get("X-Forwarded-Host"), record.Domain) {
					// check cookie expiration
					if record.Expires.After(time.Now()) {
						Info.Printf(
							"%d, URL:%s%s, %s\n",
							http.StatusOK,
							r.Header.Get("X-Forwarded-Host"),
							r.URL,
							messageValidCaptchaCookie,
						)

						return // cookie is valid
					}
				}
			}
		}
	}

	Info.Printf(
		"%d, URL:%s%s, %s\n",
		http.StatusUnauthorized,
		r.Header.Get("X-Forwarded-Host"),
		r.URL,
		messageInvalidCaptchaCookie,
	)

	// return proper HTTP error
	http.Error(w, messageInvalidCaptchaCookie, http.StatusUnauthorized)
}
