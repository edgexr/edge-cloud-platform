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

package vsphere

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/edgexr/edge-cloud/log"
)

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// GetConsoleSessionCookie does a UI login with the console user to get a cookie which can then
// be used to login remotely to the VM console.  The login is a 3 part process
// 1) GET to UI login Page
// 2) Redirect to SAML Request URL
// 3) POST to SSO login page with form data based on SAMLResponse
func (v *VSpherePlatform) GetVCenterConsoleSessionCookie(ctx context.Context) (string, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "GetConsoleSessionCookie")

	consoleUser := v.GetVCenterConsoleUser()
	consolePass := v.GetVCenterConsolePassword()
	if consoleUser == "" || consolePass == "" {
		return "", fmt.Errorf("vcenter console credentials not configured in vault")
	}
	insecure := v.GetVCenterInsecure() == "true"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	client := &http.Client{Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	vchost, _, err := v.GetVCenterAddress()
	if err != nil {
		return "", err
	}

	// first we go to the login URL
	uiLoginUrl := "https://" + vchost + "/ui/login"
	log.SpanLog(ctx, log.DebugLevelInfra, "Login to vcenter via GET", "uiLoginUrl", uiLoginUrl)
	req, _ := http.NewRequest("GET", uiLoginUrl, nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Could not reach VCenter login page, %v", err)
	}
	defer resp.Body.Close()
	hdrs := resp.Header

	// we should get a redirect with a location header
	locationHdr, ok := hdrs["Location"]
	if !ok {
		return "", fmt.Errorf("No location redirect from vcenter login page")
	}
	if len(locationHdr) != 1 {
		return "", fmt.Errorf("unexpected length of location redirect header")
	}
	samlLocation := locationHdr[0]
	log.SpanLog(ctx, log.DebugLevelInfra, "received redirect to location", "redirectLocation", samlLocation)
	samlRedirSetCookie, ok := hdrs["Set-Cookie"]
	if !ok {
		// we expect to get a session cookie back
		return "", fmt.Errorf("No cookies received from vcenter login page")
	}

	// now post to the redirected response.  This is a SAML2 SSO URL
	req, err = http.NewRequest("POST", samlLocation, nil)
	if err != nil {
		return "", fmt.Errorf("Error creating new POST request to location %s -- %v", samlLocation, err)
	}
	req.SetBasicAuth(consoleUser, consolePass)
	req.Header.Add("Cookie", samlRedirSetCookie[0])
	req.Header.Add("Referer", samlLocation)

	// in addition to basic auth we add a castle auth header with the same creds.
	castleAuth := basicAuth(consoleUser, consolePass)
	form := url.Values{}
	form.Add("CastleAuthorization", "Basic "+castleAuth)
	log.SpanLog(ctx, log.DebugLevelInfra, "Sending POST to redirect location", "URL", samlLocation)

	resp, err = client.PostForm(samlLocation, form) //send request as a POST with the castle login as form data
	if err != nil {
		return "", fmt.Errorf("Error in POST to vcenter SAML redirect -- %v", err)
	}
	defer resp.Body.Close()

	// now we have to parse the response, which is an HTML form with a SAMLResponse
	// it begins with input type="hidden" name="SAMLResponse" value="<<saml contents>>
	// and goes on for many lines finally ending with <input type="submit".
	samlbody, err := ioutil.ReadAll(resp.Body)
	lines := strings.Split(string(samlbody), "\n")
	formReading := false
	beginFormPattern := ".*name=\"SAMLResponse\" value=\"(\\S+)"
	endFormPattern := "(\\S*)\\s*/><input type=\"submit\""
	samlContents := ""
	breg := regexp.MustCompile(beginFormPattern)
	ereg := regexp.MustCompile(endFormPattern)
	for _, b := range lines {
		if breg.MatchString(b) {
			matches := breg.FindStringSubmatch(b)
			content := matches[1]
			samlContents += content + "\n"
			formReading = true
		} else if formReading {
			// we are within the form
			if ereg.MatchString(b) {
				// end of the form
				matches := ereg.FindStringSubmatch(b)
				content := matches[1]
				content = strings.ReplaceAll(content, "\"", "")
				samlContents += content + "\n"
			} else {
				//middle of the form
				samlContents += b + "\n"
			}
		}
	}

	//finally we post to the websso page with the SAML contents as a form
	form = url.Values{}
	form.Add("SAMLResponse", samlContents)
	ssoUrl := "https://" + vchost + "/ui/saml/websso/sso"
	req, err = http.NewRequest("POST", ssoUrl, strings.NewReader(form.Encode()))
	req.Header.Add("Referer", samlLocation)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Cookie", samlRedirSetCookie[0])
	reqtxt := fmt.Sprintf("%+v", req)
	log.SpanLog(ctx, log.DebugLevelInfra, "sending POST", "URL", ssoUrl, "req", reqtxt)
	resp, err = client.Do(req) //send request
	if err != nil {
		return "", fmt.Errorf("Error in POST to SSO with SAMLResponse")
	}

	defer resp.Body.Close()
	ssoCookies := resp.Cookies() //save cookies
	if len(ssoCookies) == 0 {
		return "", fmt.Errorf("No cookies in response to SSO")
	}
	for _, c := range ssoCookies {
		log.SpanLog(ctx, log.DebugLevelInfra, "SSO Cookie received", "Name", c.Name)
		if c.Name == "VSPHERE-UI-JSESSIONID" {
			return c.String(), nil
		}
	}
	return "", fmt.Errorf("unable to get vsphere ui session cookie")
}
