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

package edgeturnclient

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
)

func ReadConsoleURL(consoleUrl string, cookies []*http.Cookie) (string, error) {
	req, err := http.NewRequest("GET", consoleUrl, nil)
	if err != nil {
		return "", err
	}

	if cookies != nil {
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	options := cookiejar.Options{}

	jar, err := cookiejar.New(&options)
	if err != nil {
		return "", err
	}

	client := &http.Client{
		Transport: tr,
		Jar:       jar,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// For some reason this client is not getting 302,
	// instead it gets 502. It works fine for curl & wget
	if resp.StatusCode == http.StatusBadGateway {
		if resp.Request.URL.String() != consoleUrl {
			return ReadConsoleURL(resp.Request.URL.String(), resp.Cookies())
		}
	}
	return string(contents), nil
}
