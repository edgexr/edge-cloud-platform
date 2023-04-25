package common

import (
	"fmt"
	"testing"

	"github.com/test-go/testify/require"
)

func TestRemoveTrailingZeros(t *testing.T) {
	tests := []struct {
		in  string
		out string
	}{{
		"1000", "1000", // identity tests
	}, {
		"100.001", "100.001",
	}, {
		"1239", "1239",
	}, {
		"-3030.012345931", "-3030.012345931",
	}, {
		"1", "1",
	}, {
		"0", "0",
	}, {
		"0000", "0000",
	}, {
		"", "",
	}, {
		"100.0", "100", // remove trailing zeros
	}, {
		"987.12300", "987.123",
	}, {
		"101.1001000", "101.1001",
	}, {
		"0.00001000", "0.00001",
	}, {
		"00.00", "00",
	}, {
		".", "",
	}, {
		"100.", "100",
	}}
	for _, test := range tests {
		out := RemoveTrailingZeros(test.in)
		require.Equal(t, test.out, out)
	}
}

func TestGeoLocation(t *testing.T) {
	lat, long := float64(1.54234), float64(-2.123445)
	str := GenGeoLocation(lat, long)
	require.Equal(t, "1.5423,-2.1234", str)

	// leading zeros
	lat, long = float64(0.000111111), float64(-0.0001111111)
	str = GenGeoLocation(lat, long)
	require.Equal(t, "0.0001,-0.0001", str)

	// max values
	lat, long = float64(90.0), float64(-180.0)
	str = GenGeoLocation(lat, long)
	require.Equal(t, "90,-180", str)

	// 4-digit decimal precision is after decimal, not entire number
	lat, long = float64(-89.199199), float64(179.1991999)
	str = GenGeoLocation(lat, long)
	require.Equal(t, "-89.1992,179.1992", str)

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
