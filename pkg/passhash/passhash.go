// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package passhash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/xdg-go/pbkdf2"
)

// As computing power grows, we should increase iter and salt bytes
var PasshashIter = 10000
var PasshashKeyBytes = 32
var PasshashSaltBytes = 8

func Passhash(pw, salt []byte, iter int) []byte {
	return pbkdf2.Key(pw, salt, iter, PasshashKeyBytes, sha256.New)
}

func NewPasshash(password string) (passhash, salt string, iter int) {
	saltb := make([]byte, PasshashSaltBytes)
	rand.Read(saltb)
	pass := Passhash([]byte(password), saltb, PasshashIter)
	return base64.StdEncoding.EncodeToString(pass),
		base64.StdEncoding.EncodeToString(saltb), PasshashIter
}

func PasswordMatches(password, passhash, salt string, iter int) (bool, error) {
	sa, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false, err
	}
	ph := Passhash([]byte(password), sa, iter)
	phenc := base64.StdEncoding.EncodeToString(ph)
	return phenc == passhash, nil
}

const BasicPrefix = "Basic "

func EncodeBasicAuth(username, password string) string {
	auth := username + ":" + password
	return BasicPrefix + base64.StdEncoding.EncodeToString([]byte(auth))
}

func DecodeBasicAuth(auth string) (username, password string, ok bool) {
	if !strings.HasPrefix(auth, BasicPrefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(BasicPrefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}
