package main

import (
	"net/http"
	"time"
)

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
