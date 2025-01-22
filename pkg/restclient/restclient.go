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

package restclient

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/apicomm"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/gorilla/websocket"
	"github.com/mitchellh/mapstructure"
)

const TokenTypeBearer = "Bearer"

type Client struct {
	SkipVerify bool
	Debug      bool
	TokenType  string
	// To allow testing of midstream failures, we need to wait until
	// some stream messages have been received before signaling to the
	// sender that it's ok to generate an error.
	MidstreamFailChs map[string]chan bool
	// Test transport for mocking unit tests
	TestTransport http.RoundTripper
	// Print input data transformations
	PrintTransformations bool
	Timeout              time.Duration
	AuditLogFunc         func(data *AuditLogData)
	ParseErrorFunc       func(resBody []byte) error
}

type AuditLogData struct {
	Method          string
	Url             *url.URL
	ReqContentType  string
	ReqHeader       http.Header
	ReqBody         []byte
	Status          int
	RespContentType string
	RespHeader      http.Header
	RespBody        []byte
	Err             error
	Start           time.Time
	End             time.Time
}

func (s *Client) PostJsonSend(uri, token string, reqData interface{}, queryParams map[string]string) (*http.Response, error) {
	return s.HttpJsonSendReq("POST", uri, token, reqData, nil, queryParams)
}

func (s *Client) PostJson(uri, token string, reqData interface{}, replyData interface{}, queryParams map[string]string) (int, error) {
	status, _, err := s.HttpJsonSend("POST", uri, token, reqData, replyData, nil, queryParams, nil)
	return status, err
}

type fileData struct {
	Name string
	Data []byte
}

type MultiPartFormData struct {
	fields    map[string]interface{}
	files     map[string]*os.File
	dataFiles map[string]fileData
}

func NewMultiPartFormData() *MultiPartFormData {
	data := MultiPartFormData{
		fields:    make(map[string]interface{}),
		files:     make(map[string]*os.File),
		dataFiles: make(map[string]fileData),
	}
	return &data
}

func (s *MultiPartFormData) AddField(key string, val interface{}) {
	s.fields[key] = val
}

func (s *MultiPartFormData) AddFile(key string, val *os.File) {
	s.files[key] = val
}

func (s *MultiPartFormData) AddFileData(key, fileName string, data []byte) {
	s.dataFiles[key] = fileData{
		Name: fileName,
		Data: data,
	}
}

func (s *MultiPartFormData) Write(buf *bytes.Buffer) (string, error) {
	wr := multipart.NewWriter(buf)
	for key, val := range s.fields {
		var data []byte
		v := reflect.ValueOf(val)
		if v.Kind() == reflect.String {
			// use reflect instead of type cast to bypass
			// enum string types, and treat them as strings.
			str := v.String()
			data = []byte(str)
		} else {
			var err error
			data, err = json.Marshal(val)
			if err != nil {
				return "", fmt.Errorf("multipart form-data failed to JSON marshal field %s: %s", key, err)
			}
		}
		fw, err := wr.CreateFormField(key)
		if err != nil {
			return "", err
		}
		_, err = fw.Write(data)
		if err != nil {
			return "", err
		}
	}
	for key, file := range s.files {
		fw, err := wr.CreateFormFile(key, file.Name())
		if err != nil {
			return "", err
		}
		_, err = io.Copy(fw, file)
		if err != nil {
			return "", err
		}
	}
	for key, file := range s.dataFiles {
		fw, err := wr.CreateFormFile(key, file.Name)
		if err != nil {
			return "", err
		}
		_, err = fw.Write(file.Data)
		if err != nil {
			return "", err
		}
	}
	wr.Close()
	return wr.FormDataContentType(), nil
}

func (s *Client) HttpJsonSendReq(method, uri, token string, reqData interface{}, headerVals http.Header, queryParams map[string]string) (*http.Response, error) {
	var body io.Reader
	var datastr string
	contentType := "application/json"
	if reqData != nil {
		// Note that if reqData is a generic map, it must be in the
		// JSON namspace, because it is marshaled and sent directly.
		if str, ok := reqData.(string); ok {
			// assume string is json data
			body = bytes.NewBuffer([]byte(str))
			datastr = str
		} else if mpfd, ok := reqData.(*MultiPartFormData); ok {
			bd := &bytes.Buffer{}
			var err error
			contentType, err = mpfd.Write(bd)
			if err != nil {
				return nil, err
			}
			body = bd
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
	req.Header.Set("Content-Type", contentType)
	tokenType := s.TokenType
	if tokenType == "" {
		tokenType = TokenTypeBearer
	}
	if token != "" {
		req.Header.Add("Authorization", tokenType+" "+token)
		req.Header.Add("x-api-key", token)
	}
	for k, vals := range headerVals {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("accept") == "" {
		// some APIs require that we specify the accept header;
		// since none set by caller, assume we accept json
		req.Header.Set("accept", "application/json")
	}
	if queryParams != nil {
		vals := req.URL.Query()
		for k, v := range queryParams {
			vals.Add(k, v)
		}
		req.URL.RawQuery = vals.Encode()
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
	if s.TestTransport != nil {
		tr = s.TestTransport
	}

	if s.Debug {
		curlcmd := fmt.Sprintf(`curl -X %s -H "Content-Type: application/json" %q`, method, req.URL.String())
		tokenType := s.TokenType
		if tokenType == "" {
			tokenType = TokenTypeBearer
		}
		if token != "" {
			curlcmd += fmt.Sprintf(` -H "Authorization: %s ${TOKEN}"`, tokenType)
		}
		if s.SkipVerify {
			curlcmd += " -k"
		}
		if datastr != "" {
			curlcmd += ` --data-raw '` + datastr + `'`
		}
		fmt.Printf("%s\n", curlcmd)
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   s.Timeout,
	}
	reqBody := []byte{}
	start := time.Now()
	if s.AuditLogFunc != nil && contentType == "application/json" {
		if req.Body != nil {
			reqBody, _ = ioutil.ReadAll(req.Body)
		}
		req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))
	} else if mpfd, ok := reqData.(*MultiPartFormData); ok && s.AuditLogFunc != nil {
		reqBody, _ = json.Marshal(mpfd.fields)
	}

	// send request
	resp, err := client.Do(req)

	// audit logging
	resBody := []byte{}
	respContentType := "?"
	status := 0
	if resp != nil {
		respContentType = resp.Header.Get("Content-Type")
		status = resp.StatusCode
	}
	if s.AuditLogFunc != nil && resp != nil && strings.Contains(respContentType, "application/json") {
		if resp.Body != nil {
			resBody, _ = ioutil.ReadAll(resp.Body)
		}
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(resBody))
	}
	if s.AuditLogFunc != nil {
		data := AuditLogData{
			Method:          req.Method,
			Url:             req.URL,
			ReqContentType:  contentType,
			ReqHeader:       req.Header,
			ReqBody:         reqBody,
			Status:          status,
			RespContentType: respContentType,
			RespBody:        resBody,
			Err:             err,
			Start:           start,
			End:             time.Now(),
		}
		s.AuditLogFunc(&data)
	}
	return resp, err
}

func (s *Client) HttpJsonSend(method, uri, token string, reqData interface{}, replyData interface{}, headerVals http.Header, queryParams map[string]string, okStatuses map[int]struct{}) (int, http.Header, error) {
	resp, err := s.HttpJsonSendReq(method, uri, token, reqData, headerVals, queryParams)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s client do failed, %s", method, uri, err.Error())
	}
	okStatus := false
	if okStatuses == nil {
		okStatus = resp.StatusCode == http.StatusOK
	} else {
		_, okStatus = okStatuses[resp.StatusCode]
	}
	defer resp.Body.Close()
	if okStatus && replyData != nil {
		err := json.NewDecoder(resp.Body).Decode(replyData)
		if err != nil && err != io.EOF {
			return resp.StatusCode, nil, fmt.Errorf("%s %s decode resp failed, %v", method, uri, err)
		}
	}
	if !okStatus {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, nil, err
		}
		var reterr error
		if s.ParseErrorFunc != nil {
			reterr = s.ParseErrorFunc(body)
		} else {
			res := apicomm.Result{}
			err = json.Unmarshal(body, &res)
			if err != nil {
				// string error
				reterr = fmt.Errorf("%s", string(body))
			} else {
				reterr = errors.New(res.Message)
			}
		}
		return resp.StatusCode, nil, reterr
	}
	return resp.StatusCode, resp.Header, nil
}

func (s *Client) PostJsonStreamOut(uri, token string, reqData, replyData interface{}, queryParams map[string]string, replyReady func()) (int, error) {
	if strings.Contains(uri, "ws/api/v1") {
		return s.HandleWebsocketStreamOut(uri, token, nil, reqData, replyData, queryParams, replyReady)
	} else {
		return s.handleHttpStreamOut(uri, token, reqData, replyData, queryParams, replyReady)
	}
}

func (s *Client) handleHttpStreamOut(uri, token string, reqData, replyData interface{}, queryParams map[string]string, replyReady func()) (int, error) {
	resp, err := s.PostJsonSend(uri, token, reqData, queryParams)
	if err != nil {
		return 0, fmt.Errorf("post %s client do failed, %s", uri, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, err
		}
		res := apicomm.Result{}
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
	payload := apicomm.StreamPayload{}
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

func (s *Client) HandleWebsocketStreamOut(uri, token string, reader *bufio.Reader, reqData, replyData interface{}, queryParams map[string]string, replyReady func()) (int, error) {
	wsPayload, ok := replyData.(*apicomm.WSStreamPayload)
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

func (s *AuditLogData) GetEventTags() map[string]string {
	return map[string]string{
		"method":      s.Method,
		"remoteurl":   s.Url.String(),
		"reqheaders":  util.GetHeadersString(s.ReqHeader),
		"request":     string(s.ReqBody),
		"status":      fmt.Sprintf("%d", s.Status),
		"response":    string(s.RespBody),
		"respheaders": util.GetHeadersString(s.RespHeader),
	}
}
