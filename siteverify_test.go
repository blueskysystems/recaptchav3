package recaptchav3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestSiteVerify_Live(t *testing.T) {
	// arrange
	expected := Response{
		Success:     false,
		Score:       0,
		Action:      "",
		ChallengeTS: time.Time{},
		Hostname:    "",
		ErrorCodes:  []string{"invalid-input-response", "invalid-input-secret"},
		err:         nil,
	}

	// act
	actual := SiteVerify(context.Background(), "test", "test", "")

	// assert
	assertResponseEqual(t, expected, actual)
}

func TestSiteVerify_SuccessWithRemoteIP(t *testing.T) {
	// arrange
	challengeTS := time.Now().UTC()

	var (
		ctx          = context.Background()
		secretKey    = "ab&c"
		captchaToken = "de=f"
		remoteIP     = "127.0.0.1"
	)

	expected := Response{
		Success:     true,
		Score:       0,
		Action:      "register",
		ChallengeTS: challengeTS,
		Hostname:    "",
		ErrorCodes:  nil,
		err:         nil,
	}

	ts := newTestServer(challengeTS, nil)
	defer ts.Close()

	// act
	actual := siteVerify(ctx, secretKey, captchaToken, remoteIP, ts.URL)

	// assert
	assertResponseEqual(t, expected, actual)
}

func TestSiteVerify_SuccessWithoutRemoteIP(t *testing.T) {
	// arrange
	challengeTS := time.Now().UTC()

	var (
		ctx          = context.Background()
		secretKey    = "ab&c"
		captchaToken = "de=f"
		remoteIP     = ""
	)

	expected := Response{
		Success:     true,
		Score:       0,
		Action:      "register",
		ChallengeTS: challengeTS,
		Hostname:    "",
		ErrorCodes:  nil,
		err:         nil,
	}

	ts := newTestServer(challengeTS, nil)
	defer ts.Close()

	// act
	actual := siteVerify(ctx, secretKey, captchaToken, remoteIP, ts.URL)

	// assert
	assertResponseEqual(t, expected, actual)
}

func TestSiteVerify_NilContext(t *testing.T) {
	// arrange
	challengeTS := time.Now().UTC()

	var (
		ctx          context.Context = nil
		secretKey                    = "abc"
		captchaToken                 = "def"
		remoteIP                     = "127.0.0.1"
	)

	expected := Response{
		Success:     false,
		Score:       0,
		Action:      "",
		ChallengeTS: time.Time{},
		Hostname:    "",
		ErrorCodes:  nil,
		err:         errors.New("recaptchav3: net/http: nil Context"),
	}

	ts := newTestServer(challengeTS, nil)
	defer ts.Close()

	// act
	actual := siteVerify(ctx, secretKey, captchaToken, remoteIP, ts.URL)

	// assert
	assertResponseEqual(t, expected, actual)
}

func TestSiteVerify_HTTP500(t *testing.T) {
	// arrange
	challengeTS := time.Now().UTC()

	var (
		ctx          = context.Background()
		secretKey    = "abc"
		captchaToken = "def"
		remoteIP     = "127.0.0.1"
		handler      = func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
		}
	)

	expected := Response{
		err: errors.New("recaptchav3: http: 500 Internal Server Error, body: ''"),
	}

	ts := newTestServer(challengeTS, handler)
	defer ts.Close()

	// act
	actual := siteVerify(ctx, secretKey, captchaToken, remoteIP, ts.URL)

	// assert
	assertResponseEqual(t, expected, actual)
}

func TestSiteVerify_BadJSONResponse(t *testing.T) {
	// arrange
	challengeTS := time.Now().UTC()

	var (
		ctx          = context.Background()
		secretKey    = "abc"
		captchaToken = "def"
		remoteIP     = "127.0.0.1"
		handler      = func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("bogus response"))
		}
	)

	expected := Response{
		err: errors.New("recaptchav3: error decoding json: " +
			"invalid character 'b' looking for beginning of value, body: 'bogus response'"),
	}

	ts := newTestServer(challengeTS, handler)
	defer ts.Close()

	// act
	actual := siteVerify(ctx, secretKey, captchaToken, remoteIP, ts.URL)

	// assert
	assertResponseEqual(t, expected, actual)
}

func TestSiteVerify_ContextTimeout(t *testing.T) {
	// arrange
	challengeTS := time.Now().UTC()

	var (
		secretKey    = "abc"
		captchaToken = "def"
		remoteIP     = "127.0.0.1"
	)

	ts := newTestServer(challengeTS, slowHTTPHandler)
	defer ts.Close()

	expected := Response{
		Success:     false,
		Score:       0,
		Action:      "",
		ChallengeTS: time.Time{},
		Hostname:    "",
		ErrorCodes:  nil,
		err:         fmt.Errorf("recaptchav3: Post %s: context deadline exceeded", ts.URL),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// act
	actual := siteVerify(ctx, secretKey, captchaToken, remoteIP, ts.URL)

	// assert
	assertResponseEqual(t, expected, actual)
}

func TestSiteVerify_ContextCanceled(t *testing.T) {
	// arrange
	challengeTS := time.Now().UTC()

	var (
		secretKey    = "abc"
		captchaToken = "def"
		remoteIP     = "127.0.0.1"
	)

	ts := newTestServer(challengeTS, slowHTTPHandler)
	defer ts.Close()

	expected := Response{
		Success:     false,
		Score:       0,
		Action:      "",
		ChallengeTS: time.Time{},
		Hostname:    "",
		ErrorCodes:  nil,
		err:         fmt.Errorf("recaptchav3: Post %s: context canceled", ts.URL),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// act
	actual := siteVerify(ctx, secretKey, captchaToken, remoteIP, ts.URL)

	// assert
	assertResponseEqual(t, expected, actual)
}

func assertResponseEqual(t *testing.T, expected, actual Response) {
	if expected.Success != actual.Success {
		t.Errorf("Success, want: '%v' got: '%v'", expected.Success, actual.Success)
	}

	if expected.Score != actual.Score {
		t.Errorf("Score, want: '%v' got: '%v'", expected.Score, actual.Score)
	}

	if expected.Action != actual.Action {
		t.Errorf("Action, want: '%v' got: '%v'", expected.Action, actual.Action)
	}

	if expected.ChallengeTS != actual.ChallengeTS {
		t.Errorf("ChallengeTS, want: '%v' got: '%v'", expected.ChallengeTS, actual.ChallengeTS)
	}

	if expected.Hostname != actual.Hostname {
		t.Errorf("Hostname, want: '%v' got: '%v'", expected.Hostname, actual.Hostname)
	}

	if !reflect.DeepEqual(expected.ErrorCodes, actual.ErrorCodes) {
		t.Errorf("ErrorCodes, want: '%v' got: '%v'", expected.ErrorCodes, actual.ErrorCodes)
	}

	if !reflect.DeepEqual(expected.err, actual.err) {
		if expected.err != nil && actual.err != nil {
			if expected.err.Error() != actual.err.Error() {
				t.Errorf("err, want: %T '%v' got: %T '%v'", expected.err, expected.err, actual.err, actual.err)
			}
		} else {
			t.Errorf("err, want: '%v' got: '%v'", expected.err, actual.err)
		}
	}
}

func newTestServer(challengeTS time.Time, customHandler http.HandlerFunc) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			// NOTE: this might get returned as "bad-request" from the real reCAPTCHA server,
			// but we want to test handling status codes from gateways or unexpected behavior.
			w.WriteHeader(http.StatusUnprocessableEntity) // 422
			return
		}

		secretKey := r.PostFormValue("secret")
		captchaToken := r.PostFormValue("response")
		_ = r.PostFormValue("remoteip")

		var errorCodes []string
		if secretKey == "" {
			errorCodes = append(errorCodes, "missing-input-secret")
		}
		if captchaToken == "" {
			errorCodes = append(errorCodes, "missing-input-response")
		}

		resp := Response{
			Success:     len(errorCodes) == 0,
			ChallengeTS: challengeTS,
			Action:      "register",
			ErrorCodes:  errorCodes,
		}

		b, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError) // 500
			return
		}

		if customHandler != nil {
			customHandler(w, r)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(b)
		}
	}))

	return ts
}

func slowHTTPHandler(w http.ResponseWriter, r *http.Request) {
	timer := time.NewTimer(100 * time.Second)
	defer timer.Stop()
	select {
	case <-r.Context().Done():
		return
	case <-timer.C:
		w.WriteHeader(200)
	}
}

func newPOSTEchoServer(echo chan<- string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			msg := fmt.Sprintf("expected method 'POST', got '%s'", r.Method)
			http.Error(w, msg, http.StatusMethodNotAllowed)
			return
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/x-www-form-urlencoded" {
			msg := fmt.Sprintf("expected Content-Type 'application/x-www-form-urlencoded', got '%s'", contentType)
			http.Error(w, msg, http.StatusUnsupportedMediaType)
			return
		}

		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		echo <- string(b)

		msg := `{"success":true,"score":0.9}`
		w.Write([]byte(msg))
	}))
}

func TestSiteVerify_SendsParamsWithRemoteIP(t *testing.T) {
	// arrange
	echo := make(chan string, 1)

	ts := newPOSTEchoServer(echo)
	defer ts.Close()

	var (
		ctx          = context.Background()
		secretKey    = "ab&c"
		captchaToken = "de=f"
		remoteIP     = "127.0.0.1"
	)

	const expected = "remoteip=127.0.0.1&response=de%3Df&secret=ab%26c"

	// act
	response := siteVerify(ctx, secretKey, captchaToken, remoteIP, ts.URL)
	if err := response.Verify("", 0, nil); err != nil {
		t.Fatal(err)
	}

	// assert
	actual := <-echo
	if expected != actual {
		t.Errorf("want: '%v' got: '%v'", expected, actual)
	}
}

func TestSiteVerify_SendsParamsWithoutRemoteIP(t *testing.T) {
	// arrange
	echo := make(chan string, 1)

	ts := newPOSTEchoServer(echo)
	defer ts.Close()

	var (
		ctx          = context.Background()
		secretKey    = "ab&c"
		captchaToken = "de=f"
	)

	const expected = "response=de%3Df&secret=ab%26c"

	// act
	response := siteVerify(ctx, secretKey, captchaToken, "", ts.URL)
	if err := response.Verify("", 0, nil); err != nil {
		t.Fatal(err)
	}

	// assert
	actual := <-echo
	if expected != actual {
		t.Errorf("want: '%v' got: '%v'", expected, actual)
	}
}

func TestSiteVerify_ReadBodyError(t *testing.T) {
	// arrange
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
	}))
	defer ts.Close()

	expected := Response{
		err: errors.New("recaptchav3: read body: unexpected EOF"),
	}

	// act
	actual := siteVerify(context.Background(), "", "", "", ts.URL)

	// assert
	assertResponseEqual(t, expected, actual)
}
