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

package ormclient

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mitchellh/mapstructure"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/cli"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

type Client struct {
	SkipVerify bool
	Debug      bool
	// To allow testing of midstream failures, we need to wait until
	// some stream messages have been received before signaling to the
	// sender that it's ok to generate an error.
	MidstreamFailChs map[string]chan bool
	// Force default transport (allows for http mocking for unit tests)
	ForceDefaultTransport bool
	// Print input data transformations
	PrintTransformations bool
}

func (s *Client) Run(apiCmd *ormctl.ApiCommand, runData *mctestclient.RunData) {
	var status int
	var err error
	uri := runData.Uri + apiCmd.Path

	if structMap, ok := runData.In.(*cli.MapData); ok {
		// Passed in generic map can be in any namespace,
		// but embedded objects must not have been squashed,
		// which is what json does. So it's recommended to
		// avoid Json namespaces unless they are generated
		// from objects without marshaling.
		// The embedded hierarchy must be present, because the same
		// map data gets passed to cliwrapper and ormclient clients
		// in mctestclient generated funcs for Update/Show.
		if s.PrintTransformations {
			fmt.Printf("%s: transforming map (%s) %#v to map (JsonNamespace)\n", log.GetLineno(0), structMap.Namespace.String(), runData.In)
		}
		jsonMap, err := cli.JsonMap(structMap, apiCmd.ReqData)
		if err != nil {
			runData.RetStatus = 0
			runData.RetError = err
			return
		}
		if s.PrintTransformations {
			fmt.Printf("%s: transformed to map (JsonNamespace) %#v\n", log.GetLineno(0), jsonMap.Data)
		}
		runData.In = jsonMap.Data
	}

	if apiCmd.StreamOut {
		// ReplyData should be a pointer to a single object,
		// but runData.Out should be a slice of those objects.
		// Allocate a new object to store the streamed back data,
		// and then add that to the list passed in by the caller.
		objType := reflect.TypeOf(apiCmd.ReplyData)
		if objType.Kind() == reflect.Ptr {
			objType = objType.Elem()
		}
		buf := reflect.New(objType) // pointer to zero'd object

		arrV := reflect.ValueOf(runData.Out)
		if arrV.Kind() == reflect.Ptr {
			arrV = arrV.Elem()
		}
		status, err = s.PostJsonStreamOut(uri, runData.Token, runData.In, buf.Interface(), func() {
			arrV.Set(reflect.Append(arrV, reflect.Indirect(buf)))
		})
	} else {
		status, err = s.PostJson(uri, runData.Token, runData.In, runData.Out)
	}
	runData.RetStatus = status
	runData.RetError = err
}

func (s *Client) PostJsonSend(uri, token string, reqData interface{}) (*http.Response, error) {
	return s.HttpJsonSendReq("POST", uri, token, reqData)
}

func (s *Client) PostJson(uri, token string, reqData interface{}, replyData interface{}) (int, error) {
	return s.HttpJsonSend("POST", uri, token, reqData, replyData)
}

func (s *Client) HttpJsonSendReq(method, uri, token string, reqData interface{}) (*http.Response, error) {
	var body io.Reader
	var datastr string
	if reqData != nil {
		// Note that if reqData is a generic map, it must be in the
		// JSON namspace, because it is marshaled and sent directly.
		str, ok := reqData.(string)
		if ok {
			// assume string is json data
			body = bytes.NewBuffer([]byte(str))
			datastr = str
		} else {
			if s.PrintTransformations {
				fmt.Printf("%s: marshaling input %#v to json\n", log.GetLineno(0), reqData)
			}
			out, err := json.Marshal(reqData)
			if err != nil {
				return nil, fmt.Errorf("%s %s marshal req failed, %s", method, uri, err.Error())
			}
			body = bytes.NewBuffer(out)
			datastr = string(out)
			if s.PrintTransformations {
				fmt.Printf("%s: marshaled to json %s\n", log.GetLineno(0), datastr)
			}
		}
	} else {
		body = nil
	}

	req, err := http.NewRequest(method, uri, body)
	if err != nil {
		return nil, fmt.Errorf("%s %s http req failed, %s", method, uri, err.Error())
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
		req.Header.Add("x-api-key", token)
	}
	tlsConfig := &tls.Config{}
	if s.SkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	var tr http.RoundTripper
	tr = &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}
	if s.ForceDefaultTransport {
		tr = http.DefaultTransport
	}
	if s.Debug {
		curlcmd := fmt.Sprintf(`curl -X %s "%s" -H "Content-Type: application/json"`, method, uri)
		if token != "" {
			curlcmd += ` -H "Authorization: Bearer ${TOKEN}"`
		}
		if s.SkipVerify {
			curlcmd += " -k"
		}
		if datastr != "" {
			curlcmd += ` --data-raw '` + datastr + `'`
		}
		fmt.Printf("%s\n", curlcmd)
	}

	client := &http.Client{Transport: tr}
	return client.Do(req)
}

func (s *Client) HttpJsonSend(method, uri, token string, reqData interface{}, replyData interface{}) (int, error) {
	resp, err := s.HttpJsonSendReq(method, uri, token, reqData)
	if err != nil {
		return 0, fmt.Errorf("%s %s client do failed, %s", method, uri, err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && replyData != nil {
		err = json.NewDecoder(resp.Body).Decode(replyData)
		if err != nil && err != io.EOF {
			return resp.StatusCode, fmt.Errorf("%s %s decode resp failed, %v", method, uri, err)
		}
	}
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, err
		}
		res := ormapi.Result{}
		err = json.Unmarshal(body, &res)
		if err != nil {
			// string error
			return resp.StatusCode, fmt.Errorf("%s", body)
		}
		return resp.StatusCode, errors.New(res.Message)
	}
	return resp.StatusCode, nil
}

func (s *Client) PostJsonStreamOut(uri, token string, reqData, replyData interface{}, replyReady func()) (int, error) {
	if strings.Contains(uri, "ws/api/v1") {
		return s.HandleWebsocketStreamOut(uri, token, nil, reqData, replyData, replyReady)
	} else {
		return s.handleHttpStreamOut(uri, token, reqData, replyData, replyReady)
	}
}

func (s *Client) handleHttpStreamOut(uri, token string, reqData, replyData interface{}, replyReady func()) (int, error) {
	resp, err := s.PostJsonSend(uri, token, reqData)
	if err != nil {
		return 0, fmt.Errorf("post %s client do failed, %s", uri, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, err
		}
		res := ormapi.Result{}
		err = json.Unmarshal(body, &res)
		if err != nil {
			// string error
			return resp.StatusCode, fmt.Errorf("%s", body)
		}
		return resp.StatusCode, errors.New(res.Message)
	}
	if ch, ok := s.MidstreamFailChs[uri]; ok {
		ch <- true
	}
	payload := ormapi.StreamPayload{}
	if replyData != nil {
		payload.Data = replyData
	}

	dec := json.NewDecoder(resp.Body)
	for {
		if replyData != nil {
			// clear passed in buffer for next iteration.
			// replyData must be pointer to object.
			ClearObject(replyData)
		}

		payload.Result = nil
		err := dec.Decode(&payload)
		if err != nil {
			if err == io.EOF {
				break
			}
			return resp.StatusCode, fmt.Errorf("post %s decode resp failed, %s", uri, err.Error())
		}
		if payload.Result != nil {
			return resp.StatusCode, errors.New(payload.Result.Message)
		}
		if replyReady != nil {
			replyReady()
		}
	}
	return resp.StatusCode, nil
}

func (s *Client) WebsocketConn(uri, token string, reqData interface{}) (*websocket.Conn, error) {
	var body []byte
	if reqData != nil {
		str, ok := reqData.(string)
		if ok {
			// assume string is json data
			body = []byte(str)
		} else {
			out, err := json.Marshal(reqData)
			if err != nil {
				return nil, fmt.Errorf("post %s marshal req failed, %s", uri, err.Error())
			}
			if s.Debug {
				fmt.Printf("posting %s\n", string(out))
			}
			body = out
		}
	} else {
		body = nil
	}

	var ws *websocket.Conn
	var err error
	if strings.HasPrefix(uri, "wss") {
		d := websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 45 * time.Second,
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		}
		ws, _, err = d.Dial(uri, nil)
	} else {
		ws, _, err = websocket.DefaultDialer.Dial(uri, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("websocket connect to %s failed, %s", uri, err.Error())
	}

	// Authorize JWT with server
	authData := fmt.Sprintf(`{"token": "%s"}`, token)
	if err := ws.WriteMessage(websocket.TextMessage, []byte(authData)); err != nil {
		return nil, fmt.Errorf("websocket auth to %s failed with data %v, %s", uri, authData, err.Error())
	}

	// Send request data
	if err := ws.WriteMessage(websocket.TextMessage, []byte(body)); err != nil {
		return nil, fmt.Errorf("websocket send to %s failed, %s", uri, err.Error())
	}
	return ws, nil
}

func (s *Client) HandleWebsocketStreamOut(uri, token string, reader *bufio.Reader, reqData, replyData interface{}, replyReady func()) (int, error) {
	wsPayload, ok := replyData.(*ormapi.WSStreamPayload)
	if !ok {
		return 0, fmt.Errorf("response can only be of type WSStreamPayload")
	}
	ws, err := s.WebsocketConn(uri, token, reqData)
	if err != nil {
		return 0, fmt.Errorf("post %s client do failed, %s", uri, err.Error())
	}
	if reader != nil {
		go func() {
			for {
				text, err := reader.ReadString('\n')
				if err == io.EOF {
					break
				}
				if err := ws.WriteMessage(websocket.TextMessage, []byte(text)); err != nil {
					break
				}
			}
		}()
	}
	payload := wsPayload
	for {
		if payload != nil {
			// clear passed in buffer for next iteration.
			// payload must be pointer to object.
			ClearObject(payload)
		}

		err := ws.ReadJSON(&payload)
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				break
			}
			return http.StatusBadRequest, fmt.Errorf("post %s decode resp failed, %s", uri, err.Error())
		}
		if payload.Code != http.StatusOK {
			if payload.Data == nil {
				return payload.Code, nil
			}
			errRes := edgeproto.Result{}
			err = mapstructure.Decode(payload.Data, &errRes)
			if err == nil {
				return payload.Code, errors.New(errRes.Message)
			}
			return payload.Code, nil
		}
		if replyReady != nil {
			replyReady()
		}
	}
	return http.StatusOK, nil
}

func ClearObject(obj interface{}) {
	// clear passed in buffer for next iteration.
	// payload must be pointer to object.
	p := reflect.ValueOf(obj).Elem()
	p.Set(reflect.Zero(p.Type()))
}

func (s *Client) EnableMidstreamFailure(uri string, syncCh chan bool) {
	if s.MidstreamFailChs == nil {
		s.MidstreamFailChs = make(map[string]chan bool)
	}
	s.MidstreamFailChs[uri] = syncCh
}

func (s *Client) DisableMidstreamFailure(uri string) {
	delete(s.MidstreamFailChs, uri)
}

func (s *Client) EnablePrintTransformations() {
	s.PrintTransformations = true
}
