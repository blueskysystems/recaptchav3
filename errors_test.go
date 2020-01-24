package recaptchav3

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestErrBelowMinScore_ErrorString(t *testing.T) {
	// arrange
	const expected = "recaptchav3: score '0.1' less than '0.7'"

	err := &errBelowMinScore{Score: 0.1, MinScore: 0.7}

	// act
	actual := err.Error()

	// assert
	if expected != actual {
		t.Errorf("want: %v got: %v", expected, actual)
	}
}

var errBelowMinScoreCases = []struct {
	testName string

	err      error
	expected bool
}{
	{
		testName: "Equal",
		err:      &errBelowMinScore{},
		expected: true,
	},
	{
		testName: "SingleWrap",
		err:      fmt.Errorf("error: %w", &errBelowMinScore{}),
		expected: true,
	},
	{
		testName: "DoubleWrap",
		err:      fmt.Errorf("outer error: %w", fmt.Errorf("error: %w", &errBelowMinScore{})),
		expected: true,
	},
	{
		testName: "DifferentErrors",
		err:      io.EOF,
		expected: false,
	},
	{
		testName: "NilError",
		err:      nil,
		expected: false,
	},
}

func TestErrBelowMinScore_Is(t *testing.T) {
	is := (&errBelowMinScore{}).Is

	for _, c := range errBelowMinScoreCases {
		tc := c
		t.Run(tc.testName, func(t *testing.T) {
			// act
			actual := is(tc.err)

			// assert
			if tc.expected != actual {
				t.Errorf("want: %v got: %v", tc.expected, actual)
			}
		})
	}
}

func TestIsBelowMinScore(t *testing.T) {
	for _, c := range errBelowMinScoreCases {
		tc := c
		t.Run(tc.testName, func(t *testing.T) {
			// act
			actual := IsBelowMinScore(tc.err)

			// assert
			if tc.expected != actual {
				t.Errorf("want: %v got: %v", tc.expected, actual)
			}
		})
	}
}

func TestErrBelowMinScore_ErrorsIs(t *testing.T) {
	for _, c := range errBelowMinScoreCases {
		tc := c
		t.Run(tc.testName, func(t *testing.T) {
			// act
			actual := errors.Is(tc.err, &errBelowMinScore{})

			// assert
			if tc.expected != actual {
				t.Errorf("want: %v got: %v", tc.expected, actual)
			}

			t.Run("ParamsReversed", func(t *testing.T) {
				// act
				actual := errors.Is(&errBelowMinScore{}, tc.err)

				// assert
				if tc.expected != actual {
					t.Errorf("want: %v got: %v", tc.expected, actual)
				}
			})
		})
	}
}
