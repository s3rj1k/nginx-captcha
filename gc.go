package main

import (
	"fmt"
	"sync"
	"time"
)

func cleanDB(db *sync.Map) {
	for {
		// sleep inside infinite loop
		time.Sleep(30 * time.Second)
		// range over db
		db.Range(func(key interface{}, value interface{}) bool {
			// cast value to time
			if expire, ok := value.(time.Time); ok {
				// check expiration time
				if expire.Before(time.Now()) {
					// set log data
					data := fmt.Sprintf("%s, expired", key)
					Info.Println(data)
					// delete key
					db.Delete(key)
				}
			}

			return true
		})
	}
}
