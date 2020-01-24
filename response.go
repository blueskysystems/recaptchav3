package recaptchav3

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Response represents the reCAPTCHA response from SiteVerify.
type Response struct {
	// Success indicates whether the request was successful, it does not
	// indicate the user should be allowed to continue with their action.
	// See the Verify method.
	Success bool `json:"success"`
	// Score for this request (0.0 - 1.0).
	Score float64 `json:"score"`
	// Action name for this request (important to verify).
	Action string `json:"action"`
	// ChallengeTS contains the timestamp of the challenge load.
	ChallengeTS time.Time `json:"challenge_ts"`
	// Hostname of the site where the reCAPTCHA was solved.
	Hostname string `json:"hostname"`
	// ErrorCodes contains any errors with the request.
	//
	// Reference: https://developers.google.com/recaptcha/docs/verify/#error_code_reference
	//
	//  Error code                  Description
	//  missing-input-secret        The secret parameter is missing.
	//  invalid-input-secret        The secret parameter is invalid or malformed.
	//  missing-input-response      The response parameter is missing.
	//  invalid-input-response      The response parameter is invalid or malformed.
	//  bad-request                 The request is invalid or malformed.
	//  timeout-or-duplicate        The response is no longer valid: either is too old or has been used previously.
	ErrorCodes []string `json:"error-codes"`

	err error
}

// Verify verifies a response. The hostnames parameter is optional if "Verify the origin of reCAPTCHA
// solutions" is checked in https://www.google.com/recaptcha/admin under "Settings".
func (r Response) Verify(action string, minScore float64, hostnames []string) error {
	if r.err != nil {
		return r.err
	}

	if len(r.ErrorCodes) != 0 {
		return fmt.Errorf("recaptchav3: %s", strings.Join(r.ErrorCodes, ","))
	}

	if !r.Success {
		return errors.New("recaptchav3: success = false")
	}

	if err := checkHostnames(hostnames, r.Hostname); err != nil {
		return err
	}

	if r.Action != action {
		return fmt.Errorf("recaptchav3: action '%s' does not equal expected '%s'", r.Action, action)
	}

	if r.Score < minScore {
		return &errBelowMinScore{Score: r.Score, MinScore: minScore}
	}

	return nil
}

func checkHostnames(hostnames []string, hostname string) error {
	if len(hostnames) == 0 {
		return nil
	}

	found := false

	for _, hn := range hostnames {
		if hostname == hn {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("recaptchav3: hostname '%s' not in '%s'", hostname, strings.Join(hostnames, ","))
	}

	return nil
}
