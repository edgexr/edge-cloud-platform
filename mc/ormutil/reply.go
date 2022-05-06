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

package ormutil

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/util"
)

// HTTPError that bundles code with the error message.
// This differs from echo.HTTPError in two important ways,
// first the Error() func does not include the code, which
// allows us to chain error messages nicely, second the
// error message is a string (just like the builtin error),
// instead of an interface.
type HTTPError struct {
	Message  string `json:"message,omitempty"`
	Code     int    `json:"code,omitempty"`
	Internal error
}

func (s *HTTPError) Error() string {
	return s.Message
}

func NewHTTPError(code int, err string) *HTTPError {
	return &HTTPError{
		Message: err,
		Code:    code,
	}
}

type M map[string]interface{}

func Msg(msg string) *ormapi.Result {
	if len(msg) > 0 {
		msg = util.CapitalizeMessage(msg)
	}
	return &ormapi.Result{Message: msg}
}

func DbErr(err error) error {
	return fmt.Errorf("database error, " + err.Error())
}

func BindErr(err error) error {
	return err
}

// SetReply sets the reply data on a successful API call
func SetReply(c echo.Context, data interface{}) error {
	return c.JSON(http.StatusOK, data)
}

// StreamReply funcs used by alldata always send back just a status
// message, never an error - even if an error was generated. So they
// never use payload.Result, which is used to convey an error.
func StreamReply(c echo.Context, desc string, err error, hadErr *bool) {
	res := "ok"
	if err == echo.ErrForbidden {
		res = "forbidden"
		*hadErr = true
	} else if err != nil {
		res = err.Error()
		*hadErr = true
	}
	streamReplyMsg(c, desc, res)
}

func streamReplyMsg(c echo.Context, desc, res string) {
	payload := ormapi.StreamPayload{
		Data: &ormapi.Result{
			Message: fmt.Sprintf("%s: %s", desc, res),
			Code:    0,
		},
	}
	json.NewEncoder(c.Response()).Encode(payload)
	c.Response().Flush()
}

func StreamErr(c echo.Context, msg string) {
	payload := ormapi.StreamPayload{
		Result: &ormapi.Result{
			Message: msg,
		},
	}
	json.NewEncoder(c.Response()).Encode(payload)
	c.Response().Flush()
}
