package recaptchav3

import (
	"errors"
	"fmt"
)

type errBelowMinScore struct {
	Score    float64
	MinScore float64
}

func (e *errBelowMinScore) Error() string {
	return fmt.Sprintf("recaptchav3: score '%g' less than '%g'", e.Score, e.MinScore)
}

func (*errBelowMinScore) Is(err error) bool {
	var ok bool
	for !ok && err != nil {
		_, ok = err.(*errBelowMinScore)
		err = errors.Unwrap(err)
	}

	return ok
}

// IsBelowMinScore reports whether the error returned from Result.Verify
// is due to the reCAPTCHA score being below the minimum.
func IsBelowMinScore(err error) bool {
	return errors.Is(err, &errBelowMinScore{})
}
