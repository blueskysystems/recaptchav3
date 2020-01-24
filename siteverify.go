package recaptchav3

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const siteVerifyURL = "https://www.google.com/recaptcha/api/siteverify"

// SiteVerify makes a request to https://www.google.com/recaptcha/api/siteverify and returns the
// response. Use Response.Verify to verify the response.
//
// The remoteIP parameter is optional and may be left blank. If you use a load balancer or another web
// server to proxy calls to your application make sure to get the correct remote IP. In your HTTP handler,
// r.RemoteAddr will be the IP of the server calling you, likely that of the load balancer or web server.
// Instead, use X-Real-IP or the first entry in X-Forwarded-For and make sure your load balancers and web
// servers are configured to set these headers correctly.
func SiteVerify(ctx context.Context, secretKey, captchaResponse, remoteIP string) Response {
	return siteVerify(ctx, secretKey, captchaResponse, remoteIP, siteVerifyURL)
}

func siteVerify(ctx context.Context, secretKey, captchaResponse, remoteIP, postURL string) Response {
	data := make(url.Values, 3)
	data.Set("secret", secretKey)
	data.Set("response", captchaResponse)

	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, strings.NewReader(data.Encode()))
	if err != nil {
		return Response{err: fmt.Errorf("recaptchav3: %w", err)}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Response{err: fmt.Errorf("recaptchav3: %w", err)}
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Response{err: fmt.Errorf("recaptchav3: read body: %w", err)}
	}

	if resp.StatusCode != http.StatusOK {
		return Response{err: fmt.Errorf("recaptchav3: http: %s, body: '%s'", resp.Status, b)}
	}

	var obj Response
	if err = json.Unmarshal(b, &obj); err != nil {
		return Response{err: fmt.Errorf("recaptchav3: error decoding json: %w, body: '%s'", err, b)}
	}

	return obj
}
