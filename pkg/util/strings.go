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

package util

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/edgexr/jsonparser"
	"github.com/kballard/go-shellquote"
)

func isASCIILower(c byte) bool {
	return 'a' <= c && c <= 'z'
}
func isASCIIUpper(c byte) bool {
	return 'A' <= c && c <= 'Z'
}

func isASCIIDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

func CamelCase(s string) string {
	t := ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' {
			continue // Skip the underscore in s.
		}
		if isASCIIDigit(c) {
			t += string(c)
			continue
		}
		if isASCIILower(c) {
			c ^= ' ' // Make it upper case
		}
		t += string(c)
		// Convert upper case to lower case following an upper case character
		for i+1 < len(s) && isASCIIUpper(s[i+1]) {
			if i+2 < len(s) && isASCIILower(s[i+2]) {
				break
			}
			i++
			t += string(s[i] ^ ' ') // Make it lower case
		}
		// Accept lower case sequence that follows.
		for i+1 < len(s) && isASCIILower(s[i+1]) {
			i++
			t += string(s[i])
		}
	}
	return t
}

func EscapeJson(jsoninput string) string {
	r := strings.NewReplacer(
		`{`, `\{`, `}`, `\}`)
	return r.Replace(jsoninput)
}

func CapitalizeMessage(msg string) string {
	if len(msg) == 0 {
		return msg
	}
	c := msg[0]
	// Return msg if already capitalized
	if !isASCIILower(c) {
		return msg
	}
	// Capitalize first character and append to rest of msg
	t := string(msg[1:])
	c ^= ' '
	t = string(c) + t
	return t
}

const lowerCaseOffset = 'a' - 'A'

func UncapitalizeMessage(msg string) string {
	c := msg[0]
	// Return msg if already lower case
	if !isASCIIUpper(c) {
		return msg
	}
	t := string(msg[1:])
	c += lowerCaseOffset
	t = string(c) + t
	return t
}

func SplitCamelCase(name string) []string {
	out := []string{}
	if name == "" {
		return out
	}
	startIndex := 0
	for ii := 1; ii < len(name); ii++ {
		if isASCIIUpper(name[ii]) {
			out = append(out, name[startIndex:ii])
			startIndex = ii
		}
	}
	if startIndex < len(name) {
		out = append(out, name[startIndex:])
	}
	return out
}

// UnCamelCase converts camel case to lowercase separated by underscore
func UnCamelCase(name string) string {
	parts := SplitCamelCase(name)
	for ii := range parts {
		parts[ii] = strings.ToLower(parts[ii])
	}
	return strings.Join(parts, "_")
}

func QuoteArgs(cmd string) (string, error) {
	cmd = strings.TrimSpace(cmd)
	args, err := shellquote.Split(cmd)
	if err != nil {
		return "", err
	}
	for i := range args {
		args[i] = strconv.Quote(args[i])
	}
	return strings.Join(args, " "), nil
}

type JSONRedactor struct {
	keys        map[string]struct{}
	redactedVal string
}

func NewJSONRedactor(redactedVal string) *JSONRedactor {
	red := JSONRedactor{
		keys:        make(map[string]struct{}),
		redactedVal: redactedVal,
	}
	return &red
}

func (s *JSONRedactor) AddKey(key string) *JSONRedactor {
	// golang json unmarshal will do case insensitive matching of keys,
	// so we need to match keys in a case-insensitive way.
	s.keys[strings.ToLower(key)] = struct{}{}
	return s
}

func (s *JSONRedactor) Redact(jsonData []byte) ([]byte, error) {
	return jsonparser.Replacer(jsonData, func(key string) (string, bool) {
		if _, found := s.keys[strings.ToLower(key)]; found {
			return s.redactedVal, true
		}
		return "", false
	})
}

type FormUrlEncodedClearer struct {
	fields map[string]struct{}
}

func NewFormUrlEncodedClearer(fields ...string) *FormUrlEncodedClearer {
	clearer := &FormUrlEncodedClearer{
		fields: make(map[string]struct{}),
	}
	for _, f := range fields {
		clearer.fields[f] = struct{}{}
	}
	return clearer
}

func (s *FormUrlEncodedClearer) Clear(data []byte) []byte {
	body := strings.Split(string(data), "&")
	updated := false
	for ii, pair := range body {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if _, found := s.fields[kv[0]]; found {
			body[ii] = kv[0] + "=***"
			updated = true
		}
	}
	if updated {
		return []byte(strings.Join(body, "&"))
	}
	return data
}

type QueryURLClearer struct {
	params map[string]struct{}
}

func NewQueryURLClearer(params ...string) *QueryURLClearer {
	clearer := &QueryURLClearer{
		params: make(map[string]struct{}),
	}
	for _, f := range params {
		clearer.params[f] = struct{}{}
	}
	return clearer
}

func (s *QueryURLClearer) Clear(requestURI string) string {
	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return requestURI
	}
	values := u.Query()
	for k := range s.params {
		if values.Has(k) {
			values.Set(k, "___")
		}
	}
	u.RawQuery = values.Encode()
	return u.String()
}

func StringSliceEqual(a, b []string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for ii := range a {
		if a[ii] != b[ii] {
			return false
		}
	}
	return true
}

func StringSliceCopy(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

var redactHeaders = map[string]struct{}{
	"Authorization": {},
	"Set-Cookie":    {},
	"X-Api-Key":     {},
}

func GetHeadersString(header http.Header) string {
	// reformat header map into mix of single values
	// and lists, to avoid having lots of single values
	// shown as lists in logs.
	hout := make(map[string]interface{})
	for key, val := range header {
		if _, found := redactHeaders[key]; found {
			hout[key] = "****"
			continue
		}
		if len(val) == 0 {
			continue
		} else if len(val) == 1 {
			hout[key] = val[0]
		} else {
			hout[key] = val
		}
	}
	out, _ := json.Marshal(hout)
	return string(out)
}

// RemoveExtension removes extension and all trailing dots after a filename.
// Nothing will be trimmed if no filename is detected.
// This behavior is different from strings.TrimSuffix(path, filepath.Ext(path)),
// which will trim any extension and trailing dot regardless of the filename,
// i.e. ".." will become ".".
func RemoveExtension(path string) string {
	hasDot := false
	for i := len(path) - 1; i >= 0 && !os.IsPathSeparator(path[i]); i-- {
		if path[i] == '.' {
			hasDot = true
			continue
		}
		if !hasDot {
			// extension
			continue
		}
		// hit filename
		return path[:i+1]
	}
	return path
}

// SetExtension adds an extension to path if the basename of path has a filename.
// It will replace any existing extension.
func SetExtension(path, extension string) string {
	if len(path) == 0 || len(extension) == 0 {
		return path
	}
	// ensure extension starts with a '.'
	if extension[0] != '.' {
		extension = "." + extension
	}
	lastDot := -1
	extLen := 0
	fileNameLen := 0
	// traverse basename to find extension and filename
	for i := len(path) - 1; i >= 0 && !os.IsPathSeparator(path[i]); i-- {
		if path[i] == '.' {
			if lastDot == -1 {
				lastDot = i
			}
		} else {
			if lastDot == -1 {
				// extension
				extLen++
			} else {
				// filename
				fileNameLen++
			}
		}
	}
	if lastDot == -1 {
		// basename has no dot
		if extLen > 0 {
			// extension is really filename
			return path + extension
		}
		// empty string for base name (path ends in /)
		return path
	}
	if fileNameLen == 0 && extLen == 0 {
		// basename is ., .., ..., do not add extension
		return path
	}
	return path[:lastDot] + extension
}
