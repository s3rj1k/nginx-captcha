package main

import (
	"net/http"
	"strings"
	"time"
)

func validateHandle(w http.ResponseWriter, r *http.Request) {
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
