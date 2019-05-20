package main

import (
	"net/http"
	"sync"
	"time"
)

func cleanDB(db *sync.Map) {
	for {
		// sleep inside infinite loop
		time.Sleep(15 * time.Second)

		// range over db
		db.Range(func(key interface{}, val interface{}) bool {
			// cast value to captcha record
			if record, ok := val.(captchaDBRecord); ok {
				// check expiration time
				if record.Expires.Before(time.Now()) {
					Info.Printf(
						"%d, Domain:%s, Key:%s, Expires:%v %s\n",
						http.StatusOK,
						record.Domain,
						key,
						record.Expires,
						messageRecordExpired,
					)

					// delete key
					db.Delete(key)
				}
			}

			return true
		})
	}
}
