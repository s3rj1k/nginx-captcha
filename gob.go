package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"image/jpeg"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	captcha "github.com/s3rj1k/captcha"
)

// Data contains pregenerated CAPTCHAs.
type Data struct {
	Map  map[string]string
	Keys []string
}

// GetRandomKeyValue returns random key,value from database.
func (d Data) GetRandomKeyValue() (key string, value string) {
	var ok bool

	key = d.Keys[rand.Intn(len(d.Keys))]

	value, ok = d.Map[key]
	if !ok {
		panic("database values are not synchronized")
	}

	return key, value
}

// readCaptchaDB loads local CAPTCHA db, as gob encoded file, to memory.
func readCaptchaDB(path string) (Data, error) {
	var data Data

	// open data file
	f, err := os.Open(path)
	if err != nil {
		return data, fmt.Errorf("captcha db error: %w", err)
	}

	defer f.Close()

	if err := gob.NewDecoder(f).Decode(&data); err != nil {
		return data, fmt.Errorf("captcha db error: %w", err)
	}

	return data, nil
}

// generateCapcthaDB generates CAPTCHA and save them to a gob encoded file.
func generateCapcthaDB(path string, n uint) error {
	data := Data{
		Map:  make(map[string]string),
		Keys: []string{},
	}

	captchaConfig, err := captcha.NewOptions()
	if err != nil {
		return fmt.Errorf("captcha generate error: %w", err)
	}

	if err = captchaConfig.SetCharacterList(defaultCharsList); err != nil {
		return fmt.Errorf("captcha generate error: %w", err)
	}

	if err = captchaConfig.SetCaptchaTextLength(6); err != nil {
		return fmt.Errorf("captcha generate error: %w", err)
	}

	if err = captchaConfig.SetDimensions(320, 100); err != nil {
		return fmt.Errorf("captcha generate error: %w", err)
	}

	f := func() error {
		var captchaObj *captcha.Captcha

		captchaObj, err = captchaConfig.CreateImage()
		if err != nil {
			return fmt.Errorf("captcha generate error: %w", err)
		}

		var buff bytes.Buffer

		if err = jpeg.Encode(&buff, captchaObj.Image, nil); err != nil {
			return fmt.Errorf("captcha generate error: %w", err)
		}

		data.Map[getStringHash(captchaObj.Text)] = base64.StdEncoding.EncodeToString(buff.Bytes())

		return nil
	}

	startTime := time.Now()

	for {
		fmt.Printf("\r* Unique CAPTCHAs Generated: %d.", len(data.Map))

		if len(data.Map) == int(n) {
			fmt.Printf("\n* Elapsed Time: %s.\n", time.Since(startTime).String())

			break
		}

		if err = f(); err != nil {
			return err
		}
	}

	data.Keys = make([]string, 0, len(data.Map))

	fmt.Printf("* Processing Keys.\n")

	for k := range data.Map {
		data.Keys = append(data.Keys, k)
	}

	fmt.Printf("* Creating GOB File.\n")

	if _, err = os.Stat(filepath.Dir(path)); err != nil {
		if err = os.Mkdir(path, 0755); err != nil {
			return fmt.Errorf("captcha generate error: %w", err)
		}
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("captcha generate error: %w", err)
	}

	defer file.Close()

	if err = gob.NewEncoder(file).Encode(data); err != nil {
		return fmt.Errorf("captcha generate error: %w", err)
	}

	return nil
}
