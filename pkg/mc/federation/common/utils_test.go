package common

import (
	"fmt"
	"testing"

	"github.com/test-go/testify/require"
)

func TestGeoLocation(t *testing.T) {
	lat, long := float64(1.54234), float64(-2.123445)
	str := GenGeoLocation(lat, long)
	require.Equal(t, "1.54234,-2.123445", str)

	lat, long = float64(90.0), float64(-180.0)
	str = GenGeoLocation(lat, long)
	require.Equal(t, "90,-180", str)

	tests := []struct {
		in      string
		err     string
		outlat  float64
		outlong float64
	}{{
		"1.5423,-2.1234", "", 1.5423, -2.1234,
	}, {
		"1.542,  -2.1234", "", 1.542, -2.1234,
	}, {
		"1.5423  -2.1234", "Invalid geo location format", 0, 0,
	}, {
		"1.5a, -.1234", "Invalid latitude", 0, 0, // parse error
	}, {
		".5423, 2.123a", "Invalid longitude", 0, 0, // parse error
	}, {
		"92.1, 2.123", "Latitude out of bounds", 0, 0,
	}, {
		"-1.4433223,183.1", "Longitude out of bounds", 0, 0,
	}}
	for ii, test := range tests {
		desc := fmt.Sprintf("test %d: %s", ii, test.in)
		lat, long, err := ParseGeoLocation(test.in)
		if test.err == "" {
			require.Nil(t, err, desc)
			require.Equal(t, test.outlat, lat, desc)
			require.Equal(t, test.outlong, long, desc)
		} else {
			require.NotNil(t, err, desc)
			require.Contains(t, err.Error(), test.err, desc)
		}
	}
}
