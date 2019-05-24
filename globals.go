package main

import (
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	captcha "github.com/s3rj1k/captcha"
)

const (
	// defines case-insensitive list of captcha characters.
	defaultCharsList = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// authentication cookie name
	authenticationName = "t6f6e7r83mv6g8mzr4m739k6p"
	// number of seconds for authentication cookie expiration
	authenticationExpirationSeconds = 86400

	// captcha form input names
	challengeFormInputName = "challenge"
	responseFormInputName  = "response"

	// number of seconds for challenge hash expiration
	challengeExpirationSeconds = 60

	// number of nanoseconds in second
	nanoSecondsInSecond = 1000000000

	// HTTP code for non-authorized request, used in nginx redirects
	unAuthorizedAccess = http.StatusUnauthorized
)

const (
	messageOnlyGetMethod       = "only GET method"
	messageOnlyGetOrPostMethod = "only GET or POST method"
	messageOnlyPostMethod      = "only POST method"

	messageFailedCaptcha       = "captcha failure"
	messageFailedImageEncoding = "image encoder failure"

	messageFailedEntropy = "entropy failure"

	messageFailedHTMLRender   = "HTML render failure"
	messageFailedHTTPResponse = "HTTP responce failure"

	messageExpiredChallenge = "expired challenge"
	messageInvalidChallenge = "invalid challenge"
	messageInvalidResponse  = "invalid response"

	messageExpiredRecord    = "expired record"
	messageUnknownChallenge = "unknown challenge"

	messageEmptyAuthentication         = "empty authentication"
	messageExpiredAuthentication       = "authentication expired"
	messageInvalidAuthenticationDomain = "invalid authentication domain"
	messageUnknownAuthentication       = "unknown authentication"
	messageValidAuthentication         = "valid authentication"
)

type captchaDBRecord struct {
	// Domain defines valid captcha domain
	Domain string
	// Expires defines captcha TTL
	Expires time.Time
}

// nolint: gochecknoglobals
var (
	// captcha HTML template
	captchaTemplate *template.Template
	// captcha config object
	captchaConfig *captcha.Options

	// in memory key:value db
	db sync.Map

	// IP:PORT or unix socket path
	cmdAddress string
	// log date/time
	cmdLogDateTime bool
	// enable debug logging
	cmdDebug bool

	// empty favicon.ico
	favicon = []byte{
		000, 000, 001, 000, 001, 000, 016, 016,
		002, 000, 001, 000, 001, 000, 176, 000,
		000, 000, 022, 000, 000, 000, 040, 000,
		000, 000, 016, 000, 000, 000, 032, 000,
		000, 000, 001, 000, 001, 000, 000, 000,
		000, 000, 128, 000, 000, 000, 000, 000,
		000, 000, 000, 000, 000, 000, 000, 000,
		000, 000, 000, 000, 000, 000, 000, 000,
		000, 000, 255, 255, 255, 000, 000, 000,
		000, 000, 000, 000, 000, 000, 000, 000,
		000, 000, 000, 000, 000, 000, 000, 000,
		000, 000, 000, 000, 000, 000, 000, 000,
		000, 000, 000, 000, 000, 000, 000, 000,
		000, 000, 000, 000, 000, 000, 000, 000,
		000, 000, 000, 000, 000, 000, 000, 000,
		000, 000, 000, 000, 000, 000, 000, 000,
		000, 000, 000, 000, 000, 000, 255, 255,
		000, 000, 255, 255, 000, 000, 255, 255,
		000, 000, 255, 255, 000, 000, 255, 255,
		000, 000, 255, 255, 000, 000, 255, 255,
		000, 000, 255, 255, 000, 000, 255, 255,
		000, 000, 255, 255, 000, 000, 255, 255,
		000, 000, 255, 255, 000, 000, 255, 255,
		000, 000, 255, 255, 000, 000, 255, 255,
		000, 000, 255, 255, 000, 000,
	}

	// Logging levels
	Info  *log.Logger
	Error *log.Logger
	Debug *log.Logger
)
