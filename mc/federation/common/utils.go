package common

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	valid "github.com/asaskevich/govalidator"
)

func ParseGeoLocation(geoLoc string) (float64, float64, error) {
	var lat float64
	var long float64
	if geoLoc == "" {
		return lat, long, fmt.Errorf("Missing geo location")
	}
	loc := strings.Split(geoLoc, ",")
	if len(loc) != 2 {
		return lat, long, fmt.Errorf("Invalid geo location %q. Valid format: <LatInDecimal,LongInDecimal>", geoLoc)
	}
	latStr, longStr := strings.TrimSpace(loc[0]), strings.TrimSpace(loc[1])
	lat, err := strconv.ParseFloat(latStr, 64)
	if err != nil {
		return lat, long, err
	}
	if !valid.IsLatitude(latStr) {
		return lat, long, fmt.Errorf("Invalid latitude: %s", latStr)
	}

	long, err = strconv.ParseFloat(longStr, 64)
	if err != nil {
		return lat, long, err
	}
	if !valid.IsLongitude(longStr) {
		return lat, long, fmt.Errorf("Invalid longitude: %s", longStr)
	}

	return lat, long, nil
}

var nameMatch = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$")

func ValidateZoneId(zoneId string) error {
	if !nameMatch.MatchString(zoneId) {
		return fmt.Errorf("Invalid zone ID %q, valid format is %s", zoneId, nameMatch)
	}
	return nil
}

func ValidateFederationName(name string) error {
	if !nameMatch.MatchString(name) {
		return fmt.Errorf("Invalid federation name %q, valid format is %s", name, nameMatch)
	}
	return nil
}

func ValidateCountryCode(countryCode string) error {
	if countryCode == "" {
		return fmt.Errorf("Missing country code")
	}
	if valid.IsISO3166Alpha2(countryCode) {
		return nil
	}
	return fmt.Errorf("Invalid country code %q. It must be a valid ISO 3166-1 Alpha-2 code for the country", countryCode)
}
