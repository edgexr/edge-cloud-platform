package ormutil

import (
	"strings"
)

// Implements limited support for https://www.rfc-editor.org/rfc/rfc6570,
// which defines how variables are encoded in URL paths.

// Template only supports single, simple variables via {var}
type UriTemplate string

func NewUriTemplate(s string) UriTemplate {
	return UriTemplate(s)
}

func (s UriTemplate) Eval(values map[string]string) string {
	str := string(s)
	for k, v := range values {
		str = strings.ReplaceAll(str, "{"+k+"}", v)
	}
	return str
}

// EchoPath converts variables of format {var} to :var to be
// compatible with echo path parsing.
func (s UriTemplate) EchoPath() string {
	// this assumes balanced {} and no recursive or escaped {}
	out := strings.ReplaceAll(string(s), "{", ":")
	out = strings.ReplaceAll(out, "}", "")
	return out
}

func (s UriTemplate) String() string {
	return string(s)
}
