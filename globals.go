package main

import (
	"html/template"
	"log"
	"net/http"
	"regexp"
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
	challengeFormInputName = "44TQnXMjKY4h4Uv7"
	responseFormInputName  = "j4drYUqwwaC8s6rD"

	// number of seconds for challenge hash expiration
	challengeExpirationSeconds = 60

	// number of nanoseconds in second
	nanoSecondsInSecond = 1000000000

	// HTTP code for non-authorized request, used in nginx redirects
	unAuthorizedAccess = http.StatusUnauthorized

	// regex for UUIDv4 validation
	regExpUUIDv4 = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[8,9,a,b][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`
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
	messageInvalidUserAgent            = "invalid authentication user-agent"
	messageUnknownAuthentication       = "unknown authentication"
	messageValidAuthentication         = "valid authentication"
)

type captchaDBRecord struct {
	// Domain defines valid captcha domain
	Domain string
	// UserAgent stores UA that originated from HTTP request
	UserAgent string
	// Expires defines captcha TTL
	Expires time.Time

	// Address stores address that originated from HTTP request
	Address string
}

// nolint: gochecknoglobals
var (
	// captcha HTML template
	captchaTemplate *template.Template
	// captcha config object
	captchaConfig *captcha.Options

	// in memory key:value db
	db sync.Map

	// compiled RegExp for UUIDv4
	reUUID *regexp.Regexp

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
	Bot   *log.Logger
)
