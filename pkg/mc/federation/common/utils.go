// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	valid "github.com/asaskevich/govalidator"
)

// Parse the Geo Location format
func ParseGeoLocation(geoLoc string) (float64, float64, error) {
	var lat float64
	var long float64
	if geoLoc == "" {
		return lat, long, fmt.Errorf("Missing geo location")
	}
	loc := strings.Split(geoLoc, ",")
	if len(loc) != 2 {
		return lat, long, fmt.Errorf("Invalid geo location format %q. Valid format: <LatInDecimal,LongInDecimal>", geoLoc)
	}
	latStr, longStr := strings.TrimSpace(loc[0]), strings.TrimSpace(loc[1])
	lat, err := strconv.ParseFloat(latStr, 64)
	if err != nil {
		return lat, long, fmt.Errorf("Invalid latitude %q, must be a valid decimal number", latStr)
	}
	if lat < float64(-90) || lat > float64(90) {
		return lat, long, fmt.Errorf("Latitude out of bounds: %s", latStr)
	}
	long, err = strconv.ParseFloat(longStr, 64)
	if err != nil {
		return lat, long, fmt.Errorf("Invalid longitude %q, must be a valid decimal number", longStr)
	}
	if long < float64(-180) || long > float64(180) {
		return lat, long, fmt.Errorf("Longitude out of bounds: %s", longStr)
	}
	return lat, long, nil
}

// Generate a geo location string.
func GenGeoLocation(latitude, longitude float64) string {
	lat := strconv.FormatFloat(latitude, 'g', -1, 64)
	long := strconv.FormatFloat(longitude, 'g', -1, 64)
	return lat + "," + long
}

// Federation ID and Zone ID
var idMatch = regexp.MustCompile("^[a-fA-f0-9]+$")
var zoneMatch = regexp.MustCompile("^[a-zA-Z0-9-]+$")
var nameMatch = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$")

func ValidateZoneId(zoneId string) error {
	if !zoneMatch.MatchString(zoneId) {
		return fmt.Errorf("Invalid zone ID %q, valid format is %s", zoneId, zoneMatch)
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

func ValidateFederationId(fedId string) error {
	if !idMatch.MatchString(fedId) {
		return fmt.Errorf("Invalid federation ID %q, can only contain a-f, A-F, and 0-9 characters", fedId)
	}
	if len(fedId) < 8 || len(fedId) > 128 {
		return fmt.Errorf("Invalid federation ID %q, valid length is 8 to 128 characters", fedId)
	}
	return nil
}

func ValidateApiKey(apiKey string) error {
	if len(apiKey) < 8 || len(apiKey) > 128 {
		return fmt.Errorf("Invalid API key %q, valid length is 8 to 128 characters", apiKey)
	}
	return nil
}
