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

// Validation functions for validating data received
// from an external source - user input, or network data

package util

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// If new valid characters are added here, be sure to update
// the Sanitize functions below to replace the new characters.
var nameMatch = regexp.MustCompile("^[0-9a-zA-Z][-_0-9a-zA-Z .&,!]*$")
var k8sMatch = regexp.MustCompile("^[0-9a-zA-Z][-0-9a-zA-Z.]*$")
var emailMatch = regexp.MustCompile(`(.+)@(.+)\.(.+)`)
var dockerNameMatch = regexp.MustCompile(`^[0-9a-zA-Z][a-zA-Z0-9_.-]+$`)
var cliArgMatch = regexp.MustCompile(`^[0-9a-z][0-9a-z.#:]*$`)

const maxHostnameLength = 63
const maxK8sNamespaceLength = 63

// region names are used in Vault approle names, which are very
// restrictive in what characters they allow.
var regionMatch = regexp.MustCompile(`^\w+$`)

// walk through the map of names and values and validate the values
// return an error about which key had invalid value
func ValidateNames(names map[string]string) error {
	if names == nil {
		return nil
	}
	for k, v := range names {
		if v != "" && !ValidName(v) {
			return fmt.Errorf("invalid %s", k)
		}
	}
	return nil
}

func ValidName(name string) bool {
	return nameMatch.MatchString(name)
}

func ValidKubernetesName(name string) bool {
	return k8sMatch.MatchString(name)
}

func ValidDockerName(name string) bool {
	return dockerNameMatch.MatchString(name)
}

func ValidIp(ip []byte) bool {
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return false
	}
	return true
}

func ValidEmail(email string) bool {
	return emailMatch.MatchString(email)
}

func ValidRegion(name string) bool {
	return regionMatch.MatchString(name)
}

// Valid CLI args must be all lowercase, and my only contain
// alphanumeric and period, and in the case of repeated objects, colons.
func ValidCliArg(arg string) bool {
	return cliArgMatch.MatchString(arg)
}

// DockerSanitize sanitizes the name string (which is assumed to be a
// ValidName) to make it usable as a docker image name
// (no spaces and special chars other than - and . are allowed)
func DockerSanitize(name string) string {
	r := strings.NewReplacer(
		" ", "",
		"&", "-",
		",", "",
		"!", ".")
	return r.Replace(name)
}

// DNSSanitize santizies the name string for RFC 1123 DNS format.
// Valid chars are only 0-9, a-z, and '-' and cannot start or end in '-'
func DNSSanitize(name string) string {
	buf := make([]rune, len(name), len(name))
	last := len(name) - 1
	skipped := 0
	for ii, ch := range name {
		if isASCIILower(byte(ch)) || isASCIIDigit(byte(ch)) {
			buf[ii-skipped] = ch
		} else if isASCIIUpper(byte(ch)) {
			buf[ii-skipped] = ch + lowerCaseOffset
		} else if ch == '-' || ch == '_' {
			if ii == 0 || ii == last {
				skipped++
			} else {
				buf[ii-skipped] = '-'
			}
		} else {
			skipped++
		}
	}
	return string(buf[:len(name)-skipped])
}

func ValidDNSName(name string) error {
	if len(name) > 63 {
		return fmt.Errorf("invalid RFC1123 name %q, cannot be longer than 63 characters", name)
	}
	last := len(name) - 1
	for ii, ch := range name {
		if isASCIILower(byte(ch)) || isASCIIDigit(byte(ch)) {
			continue
		} else if isASCIIUpper(byte(ch)) {
			return fmt.Errorf("invalid RFC1123 name %q, does not allow upper case characters", name)
		} else if ch == '-' {
			if ii == 0 || ii == last {
				return fmt.Errorf("invalid RFC1123 name %q, cannot start or end with '-'", name)
			}
		} else {
			return fmt.Errorf("invalid RFC1123 name %q, does not allow %q", name, ch)
		}
	}
	return nil
}

// HostnameSanitize makes a valid hostname, for which the rules
// are the same as DNSSanitize, but it cannot end in '-' and cannot
// be > 63 digits
func HostnameSanitize(name string) string {
	r := DNSSanitize(name)
	if len(r) > maxHostnameLength {
		r = r[:maxHostnameLength]
	}
	return strings.TrimRight(r, "-")
}

func K8SSanitize(name string) string {
	r := strings.NewReplacer(
		"_", "-",
		" ", "",
		"&", "",
		",", "",
		"!", "")
	return strings.ToLower(r.Replace(name))
}

func K8SServiceSanitize(name string) string {
	str := DNSSanitize(name)
	if str == "" {
		return str
	}
	if !unicode.IsLetter(rune(str[0])) {
		// first character must be alpha for services
		str = "a" + str
	}
	return str
}

// K8SLabelValueSanitize sanitizes a string to use as a metadata label value
// Label values must be 63 chars or less (can be empty),
// must begin and end with alphanumerics [a-z0-9A-Z], and may contain dashes,
// underscores, dots, and alphanumerics.
func K8SLabelValueSanitize(label string) string {
	s := ""
	for i := 0; i < len(label); i++ {
		if len(s) == 63 {
			break
		}
		c := label[i]
		if (len(s) == 0 || len(s) == 62) && !isASCIILower(c) && !isASCIIUpper(c) && !isASCIIDigit(c) {
			continue
		}
		if isASCIILower(c) || isASCIIUpper(c) || isASCIIDigit(c) || c == '-' || c == '_' || c == '.' {
			s += string(c)
		}
	}
	// removing trailing invalid chars
	return strings.TrimRight(s, "._-")
}

// Namespaces are limited to 63 characters and cannot end in "-"
func NamespaceSanitize(name string) string {
	r := DNSSanitize(name)
	if len(r) > maxK8sNamespaceLength {
		r = r[:maxK8sNamespaceLength]
	}
	return strings.TrimRight(r, "-")
}

// alphanumeric plus -_. first char must be alpha, <= 255 chars.
func HeatSanitize(name string) string {
	r := strings.NewReplacer(
		" ", "",
		"&", "",
		",", "",
		"!", "")
	str := r.Replace(name)
	if str == "" {
		return str
	}
	if !unicode.IsLetter(rune(str[0])) {
		// first character must be alpha
		str = "a" + str
	}
	if len(str) > 255 {
		str = str[:254]
	}
	return str
}

func ValidObjName(name string) error {
	re := regexp.MustCompile("^[a-zA-Z0-9_\\-.]*$")
	if !re.MatchString(name) {
		return fmt.Errorf("name can only contain letters, digits, _ . -")
	}
	if err := ValidLDAPName(name); err != nil {
		return err
	}
	return nil
}

func ValidStoragePath(path string) error {
	if !ValidName(path) {
		return fmt.Errorf("Invalid path %s", path)
	}
	if path == "." || path == ".." {
		return fmt.Errorf("Invalid path %s, cannot be name . or ...", path)
	}
	if strings.Contains(path, "/") {
		return fmt.Errorf("Invalid path %s, cannot be have /", path)
	}
	return nil
}

// IsLatitudeValid checks that the latitude is within accepted ranges
func IsLatitudeValid(latitude float64) bool {
	return (latitude >= -90) && (latitude <= 90)
}

// IsLongitudeValid checks that the longitude is within accepted ranges
func IsLongitudeValid(longitude float64) bool {
	return (longitude >= -180) && (longitude <= 180)
}

func ValidateImagePath(imagePath string) error {
	url, err := ImagePathParse(imagePath)
	if err != nil {
		return fmt.Errorf("invalid image path: %v", err)
	}
	ext := filepath.Ext(url.Path)
	if ext == "" {
		return fmt.Errorf("missing filename from image path")
	}

	urlInfo := strings.Split(imagePath, "#")
	if len(urlInfo) != 2 {
		return fmt.Errorf("md5 checksum of image is required. Please append checksum to imagepath: \"<url>#md5:checksum\"")
	}
	cSum := strings.Split(urlInfo[1], ":")
	if len(cSum) != 2 {
		return fmt.Errorf("incorrect checksum format, valid format: \"<url>#md5:checksum\"")
	}
	if cSum[0] != "md5" {
		return fmt.Errorf("only md5 checksum is supported")
	}
	if len(cSum[1]) < 32 {
		return fmt.Errorf("md5 checksum must be at least 32 characters")
	}
	_, err = hex.DecodeString(cSum[1])
	if err != nil {
		return fmt.Errorf("invalid md5 checksum")
	}
	return nil
}

func ImagePathParse(imagepath string) (*url.URL, error) {
	// url.Parse requires the scheme but won't error if
	// it's not present.
	if !strings.Contains(imagepath, "://") {
		imagepath = "https://" + imagepath
	}
	return url.Parse(imagepath)
}

func ContainerVersionParse(version string) (*time.Time, error) {
	// 2nd Jan 2016
	ref_layout := "2006-01-02"
	vers, err := time.Parse(ref_layout, version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse container version: %v", err)
	}
	return &vers, nil
}

func ValidateImageVersion(imgVersion string) error {
	re := regexp.MustCompile("^[0-9a-zA-Z][-0-9a-zA-Z._]*$")
	if !re.MatchString(imgVersion) {
		return fmt.Errorf("ImageVersion can only contain letters, digits, -, ., _")
	}
	return nil
}

func ValidK8SContainerName(name string) error {
	parts := strings.Split(name, "/")
	if len(parts) == 1 {
		if !ValidKubernetesName(name) {
			return fmt.Errorf("Invalid kubernetes container name")
		}
	} else if len(parts) == 2 {
		if !ValidKubernetesName(parts[0]) {
			return fmt.Errorf("Invalid kubernetes pod name")
		}
		if !ValidKubernetesName(parts[1]) {
			return fmt.Errorf("Invalid kubernetes container name")
		}
	} else if len(parts) == 3 {
		if !ValidKubernetesName(parts[0]) {
			return fmt.Errorf("Invalid kubernetes namespace name")
		}
		if !ValidKubernetesName(parts[1]) {
			return fmt.Errorf("Invalid kubernetes pod name")
		}
		if !ValidKubernetesName(parts[2]) {
			return fmt.Errorf("Invalid kubernetes container name")
		}
	} else {
		return fmt.Errorf("Invalid kubernetes container name, should be of format '<namespace>/<PodName>/<ContainerName>'")
	}
	return nil
}
