package recaptchav3

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

const (
	defaultAction   = "homepage"
	defaultMinScore = 0.5
)

func TestResponse_Verify_SuccessWithHostnames(t *testing.T) {
	// arrange
	hostnames := []string{"example.com", "www.example.com"}

	resp := Response{
		Success:  true,
		Action:   defaultAction,
		Hostname: "example.com",
		Score:    1.0,
	}

	// act/assert
	if err := resp.Verify(defaultAction, defaultMinScore, hostnames); err != nil {
		t.Error(err)
	}
}

func TestResponse_Verify_SuccessEmptyHostnames(t *testing.T) {
	// arrange
	resp := Response{
		Success:  true,
		Action:   defaultAction,
		Hostname: "example.com",
		Score:    1.0,
	}

	// act/assert
	if err := resp.Verify(defaultAction, defaultMinScore, []string{}); err != nil {
		t.Error(err)
	}
}

func TestResponse_Verify_SuccessNilHostnames(t *testing.T) {
	// arrange
	resp := Response{
		Success:  true,
		Action:   defaultAction,
		Hostname: "example.com",
		Score:    1.0,
	}

	// act/assert
	if err := resp.Verify(defaultAction, defaultMinScore, nil); err != nil {
		t.Error(err)
	}
}

func TestResponse_Verify_RequestError(t *testing.T) {
	// arrange
	resp := Response{
		err: errors.New("recaptchav3: an error occurred"),
	}

	const expectedError = "recaptchav3: an error occurred"

	// act
	err := resp.Verify(defaultAction, defaultMinScore, nil)

	// assert
	if err == nil {
		t.Errorf("want: '%v' got: <nil>", expectedError)
	} else if expectedError != err.Error() {
		t.Errorf("want: '%v' got: '%v'", expectedError, err.Error())
	}
}

func TestResponse_Verify_ErrorCodesSingle(t *testing.T) {
	// arrange
	resp := Response{
		ErrorCodes: []string{"timeout-or-duplicate"},
	}

	const expectedError = "recaptchav3: timeout-or-duplicate"

	// act
	err := resp.Verify(defaultAction, defaultMinScore, nil)

	// assert
	if err == nil {
		t.Errorf("want: '%v' got: <nil>", expectedError)
	} else if expectedError != err.Error() {
		t.Errorf("want: '%v' got: '%v'", expectedError, err.Error())
	}
}

func TestResponse_Verify_ErrorCodesMultiple(t *testing.T) {
	// arrange
	resp := Response{
		ErrorCodes: []string{"missing-input-secret", "missing-input-response"},
	}

	const expectedError = "recaptchav3: missing-input-secret,missing-input-response"

	// act
	err := resp.Verify(defaultAction, defaultMinScore, nil)

	// assert
	if err == nil {
		t.Errorf("want: '%v' got: <nil>", expectedError)
	} else if expectedError != err.Error() {
		t.Errorf("want: '%v' got: '%v'", expectedError, err.Error())
	}
}

func TestResponse_Verify_SuccessEqualsFalse(t *testing.T) {
	// arrange
	resp := Response{
		Success: false,
	}

	const expectedError = "recaptchav3: success = false"

	// act
	err := resp.Verify(defaultAction, defaultMinScore, nil)

	// assert
	if err == nil {
		t.Errorf("want: '%v' got: <nil>", expectedError)
	} else if expectedError != err.Error() {
		t.Errorf("want: '%v' got: '%v'", expectedError, err.Error())
	}
}

func TestResponse_Verify_ActionMismatch(t *testing.T) {
	// arrange
	hostnames := []string{"example.com", "www.example.com"}

	resp := Response{
		Success:  true,
		Action:   defaultAction + "-fake",
		Hostname: "example.com",
		Score:    1.0,
	}

	expectedError := fmt.Sprintf("recaptchav3: action '%s-fake' does not equal expected '%s'",
		defaultAction, defaultAction)

	// act
	err := resp.Verify(defaultAction, defaultMinScore, hostnames)

	// assert
	if err == nil {
		t.Errorf("want: '%v' got: <nil>", expectedError)
	} else if expectedError != err.Error() {
		t.Errorf("want: '%v' got: '%v'", expectedError, err.Error())
	}
}

func TestResponse_Verify_HostnameMismatch(t *testing.T) {
	// arrange
	hostnames := []string{"example.com", "www.example.com"}

	resp := Response{
		Success:  true,
		Action:   defaultAction,
		Hostname: "fake.example.com",
		Score:    1.0,
	}

	const expectedError = "recaptchav3: hostname 'fake.example.com' not in 'example.com,www.example.com'"

	// act
	err := resp.Verify(defaultAction, defaultMinScore, hostnames)

	// assert
	if err == nil {
		t.Errorf("want: '%v' got: <nil>", expectedError)
	} else if expectedError != err.Error() {
		t.Errorf("want: '%v' got: '%v'", expectedError, err.Error())
	}
}

func TestResponse_Verify_BelowMinScore(t *testing.T) {
	// arrange
	hostnames := []string{"example.com", "www.example.com"}

	resp := Response{
		Success:  true,
		Action:   defaultAction,
		Hostname: "example.com",
		Score:    0.4,
	}

	const expectedError = "recaptchav3: score '0.4' less than '0.5'"

	// act
	err := resp.Verify(defaultAction, defaultMinScore, hostnames)

	// assert
	if err == nil {
		t.Errorf("want: '%v' got: <nil>", expectedError)
	} else if expectedError != err.Error() {
		t.Errorf("want: '%v' got: '%v'", expectedError, err.Error())
	}

	if !IsBelowMinScore(err) {
		t.Errorf("want: %T got: %T", &errBelowMinScore{}, err)
	}
}

func TestResponseSerialize(t *testing.T) {
	// arrange
	const expected = `{
  "success": true,
  "score": 0.9,
  "action": "homepage",
  "challenge_ts": "2020-01-24T14:47:44Z",
  "hostname": "example.com",
  "error-codes": []
}`

	resp := Response{
		Success:     true,
		Score:       0.9,
		Action:      "homepage",
		ChallengeTS: time.Date(2020, 01, 24, 14, 47, 44, 0, time.UTC),
		Hostname:    "example.com",
		ErrorCodes:  []string{},
	}

	// act
	b, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	// assert
	if expected != string(b) {
		t.Errorf("want:\n---\n%s\n---\n\ngot:\n---\n%s\n---\n", expected, b)
	}
}

func TestResponseDeserialize(t *testing.T) {
	// arrange
	const responseJSON = `{
  "success": true,
  "score": 0.9,
  "action": "homepage",
  "challenge_ts": "2020-01-24T14:47:44Z",
  "hostname": "example.com",
  "error-codes": []
}`

	expected := Response{
		Success:     true,
		Score:       0.9,
		Action:      "homepage",
		ChallengeTS: time.Date(2020, 01, 24, 14, 47, 44, 0, time.UTC),
		Hostname:    "example.com",
		ErrorCodes:  []string{},
	}

	// act
	var actual Response
	if err := json.Unmarshal([]byte(responseJSON), &actual); err != nil {
		t.Fatal(err)
	}

	// assert
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("want:\n---\n%v\n---\n\ngot:\n---\n%v\n---\n", expected, actual)
	}
}
