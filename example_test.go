package recaptchav3_test

import (
	"context"
	"fmt"
	"log"

	"github.com/blueskysystems/recaptchav3"
)

func ExampleSiteVerify() {
	var (
		ctx             = context.Background()
		secretKey       = "secret-key"
		captchaResponse = "captcha-response"
		remoteIP        = ""

		action             = "homepage"
		minScore           = 0.5
		hostnames []string = nil
	)

	response := recaptchav3.SiteVerify(ctx, secretKey, captchaResponse, remoteIP)
	if err := response.Verify(action, minScore, hostnames); err != nil {
		log.Fatal(err)
	}

	fmt.Println("OK")
}
