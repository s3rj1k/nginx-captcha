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

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write(favicon); err != nil {
		Error.Printf(
			"%d, RAddr:%s, URL:%s%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			messageFailedHTTPResponse,
		)
	}
}

func challengeHandle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderHandle(w, r)
	case http.MethodPost:
		validateHandle(w, r)
	default:
		Debug.Printf(
			"%d, RAddr:%s, URL:%s%s, %s\n",
			http.StatusMethodNotAllowed,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
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
		Debug.Printf(
			"%d, RAddr:%s, URL:%s%s, %s\n",
			http.StatusMethodNotAllowed,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
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
			"%d, RAddr:%s, URL:%s%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			messageFailedCaptcha,
		)

		// return proper HTTP error
		http.Error(w, messageFailedCaptcha, http.StatusInternalServerError)
		return
	}

	var buff bytes.Buffer

	// encode captcha to JPEG
	err = jpeg.Encode(&buff, captchaObj.Image, nil)
	if err != nil {
		Error.Printf(
			"%d, RAddr:%s, URL:%s%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			messageFailedImageEncoding,
		)

		// return proper HTTP error
		http.Error(w, messageFailedImageEncoding, http.StatusInternalServerError)
		return
	}

	// set how long cookie is valid
	challengeTTL := time.Duration(challengeExpirationSeconds * nanoSecondsInSecond)
	// generate expire date for captcha hash
	expires := time.Now().Add(challengeTTL)
	// generate hash of captcha string
	challenge := getStringHash(captchaObj.Text)

	Info.Printf(
		"%d, RAddr:%s, URL:%s%s, CAPTCHA:%s, Challenge:%s, TTL:%s\n",
		http.StatusOK,
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-Host"),
		r.Header.Get("X-Original-URI"),
		captchaObj.Text, challenge, challengeTTL,
	)

	// populate struct with needed data for template render
	data := struct {
		Base64             string
		TextHash           string
		ChallengeInputName string
		ResponceInputName  string
	}{
		// encode JPEG to base for data:URI
		Base64: base64.StdEncoding.EncodeToString(buff.Bytes()),
		// set captcha text hash
		TextHash: challenge,
		// form input names
		ChallengeInputName: challengeFormInputName,
		ResponceInputName:  responseFormInputName,
	}

	// store captcha hash to db
	db.Store(data.TextHash,
		captchaDBRecord{
			Domain:  r.Header.Get("X-Forwarded-Host"),
			Expires: expires,
		},
	)

	// https://www.fastly.com/blog/clearing-cache-browser
	// https://www.w3.org/TR/clear-site-data/
	w.Header().Set("Clear-Site-Data", `"cache"`)

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
			"%d, RAddr:%s, URL:%s%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			messageFailedHTMLRender,
		)

		// return proper HTTP error
		http.Error(w, messageFailedHTMLRender, http.StatusInternalServerError)
		return
	}
}

func validateHandle(w http.ResponseWriter, r *http.Request) {
	// allow only POST method
	if r.Method != http.MethodPost {
		Debug.Printf(
			"%d, RAddr:%s, URL:%s%s, %s\n",
			http.StatusMethodNotAllowed,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			messageOnlyPostMethod,
		)

		// return proper HTTP error with headers
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, messageOnlyPostMethod, http.StatusMethodNotAllowed)
		return
	}

	// get captcha answer from request form, case insensitive
	response := strings.ToUpper(strings.TrimSpace(r.PostFormValue(responseFormInputName)))
	// get hidden captcha answer hash from request form
	challenge := strings.TrimSpace(r.PostFormValue(challengeFormInputName))

	Debug.Printf(
		"%d, RAddr:%s, URL:%s%s, Responce:%s, Challenge:%s\n",
		http.StatusOK,
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-Host"),
		r.Header.Get("X-Original-URI"),
		response, challenge,
	)

	// https://www.fastly.com/blog/clearing-cache-browser
	// https://www.w3.org/TR/clear-site-data/
	w.Header().Set("Clear-Site-Data", `"cache"`)

	// lookup captcha hash in db
	val, ok := db.Load(challenge)
	if !ok {
		Info.Printf(
			"%d, RAddr:%s, URL:%s%s, Challenge:%s, %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			challenge, messageUnknownChallenge,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// check captcha hash record
	record, ok := val.(captchaDBRecord)
	if !ok {
		Error.Printf(
			"%d, RAddr:%s, URL:%s%s, Challenge:%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			challenge, messageUnknownChallenge,
		)

		// return proper HTTP error
		http.Error(w, messageUnknownChallenge, http.StatusInternalServerError)
		return
	}

	// check that captcha hash is valid for domain
	if !strings.EqualFold(r.Header.Get("X-Forwarded-Host"), record.Domain) {
		Info.Printf(
			"%d, RAddr:%s, URL:%s%s, Challenge:%s, %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			challenge, messageInvalidChallenge,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// check captcha hash expiration
	if record.Expires.Before(time.Now()) {
		Info.Printf(
			"%d, RAddr:%s, URL:%s%s, Challenge:%s, %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			challenge, messageExpiredChallenge,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// validate user inputed captcha response
	if getStringHash(response) != challenge {
		Info.Printf(
			"%d, RAddr:%s, URL:%s%s, Challenge:%s, %s\n",
			http.StatusSeeOther,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			challenge, messageInvalidResponse,
		)

		// redirect to self
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// generate ID for cookie value
	id, err := genUUID()
	if err != nil {
		Error.Printf(
			"%d, RAddr:%s, URL:%s%s, %s\n",
			http.StatusInternalServerError,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			messageFailedEntropy,
		)

		// return proper HTTP error
		http.Error(w, messageFailedEntropy, http.StatusInternalServerError)
		return
	}

	// set how long cookie is valid
	authenticationTTL := time.Duration(authenticationExpirationSeconds * nanoSecondsInSecond)
	// generate expire date for authentication hash
	expires := time.Now().Add(authenticationTTL)

	Info.Printf(
		"%d, RAddr:%s, URL:%s%s, Responce:%s, Challenge:%s, Auth:%s, TTL:%s\n",
		http.StatusOK,
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-Host"),
		r.Header.Get("X-Original-URI"),
		response, challenge, id, authenticationTTL,
	)

	// store captcha hash to db
	db.Store(id,
		captchaDBRecord{
			Domain:  r.Header.Get("X-Forwarded-Host"),
			Expires: expires,
		},
	)

	// create cookie
	http.SetCookie(w, &http.Cookie{
		Name:     authenticationName,
		Value:    id,
		Expires:  expires,
		MaxAge:   int(expires.Unix() - time.Now().Unix()),
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// redirect to self
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func authHandle(w http.ResponseWriter, r *http.Request) {
	// get challenge cookie value from request
	auth, err := r.Cookie(authenticationName)
	if err != nil || auth == nil {
		Debug.Printf(
			"%d, RAddr:%s, URL:%s%s, %s\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			messageEmptyAuthentication,
		)

		// return proper HTTP error
		http.Error(w, messageEmptyAuthentication, unAuthorizedAccess)
		return
	}

	// lookup cookie value in db
	val, ok := db.Load(auth.Value)
	if !ok {
		Debug.Printf(
			"%d, RAddr:%s, URL:%s%s, Auth:%s, %s\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			auth.Value, messageUnknownAuthentication,
		)

		// return proper HTTP error
		http.Error(w, messageUnknownAuthentication, unAuthorizedAccess)
		return
	}

	// check challenge hash record
	record, ok := val.(captchaDBRecord)
	if !ok {
		Error.Printf(
			"%d, RAddr:%s, URL:%s%s, Auth:%s, %s\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			auth.Value, messageUnknownAuthentication,
		)

		// return proper HTTP error
		http.Error(w, messageUnknownAuthentication, unAuthorizedAccess)
		return
	}

	// check that cookie is valid for domain
	if !strings.EqualFold(r.Header.Get("X-Forwarded-Host"), record.Domain) {
		Debug.Printf(
			"%d, RAddr:%s, URL:%s%s, Auth:%s, %s (%s)\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			auth.Value, messageInvalidAuthenticationDomain, record.Domain,
		)

		// return proper HTTP error
		http.Error(w, messageInvalidAuthenticationDomain, unAuthorizedAccess)
		return
	}

	// check cookie expiration
	if !record.Expires.After(time.Now()) {
		Debug.Printf(
			"%d, RAddr:%s, URL:%s%s, Auth:%s, %s\n",
			unAuthorizedAccess,
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Original-URI"),
			auth.Value, messageExpiredAuthentication,
		)

		// return proper HTTP error
		http.Error(w, messageExpiredAuthentication, unAuthorizedAccess)
	}

	Debug.Printf(
		"%d, RAddr:%s, URL:%s%s, Auth:%s, %s\n",
		http.StatusOK,
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-Host"),
		r.Header.Get("X-Original-URI"),
		auth.Value, messageValidAuthentication,
	)
}
