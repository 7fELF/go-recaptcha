// Package recaptcha handles reCaptcha (http://www.google.com/recaptcha) server side validation
package recaptcha

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

// Response from recaptcha
type Response struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

// Verifier allows to verify a recaptcha
// You can change the API URL and the http.Client
// (before you start using Verify to avoid race conditions)
type Verifier struct {
	privateKey string
	APIURL     string
	Client     *http.Client
}

const defaultAPIURL = "https://www.google.com/recaptcha/api/siteverify"

// New instance with the default URL (https://www.google.com/recaptcha/api/siteverify)
func New(privateKey string) Verifier {
	return Verifier{
		privateKey: privateKey,
		APIURL:     defaultAPIURL,
		Client:     &http.Client{Timeout: time.Second * 10},
	}
}

// Verify a recaptcha
// this function is thread safe
func (v Verifier) Verify(response string) (Response, error) {
	var resp Response

	r, err := v.Client.PostForm(
		v.APIURL,
		url.Values{
			"secret":   {v.privateKey},
			"response": {response},
		},
	)
	if err != nil {
		return resp, err
	}

	if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
		return resp, err
	}

	return resp, nil
}
