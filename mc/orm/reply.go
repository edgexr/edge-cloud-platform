package orm

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/util"
)

var echoContextError = "mobiledgexError"

type M map[string]interface{}

func Msg(msg string) *ormapi.Result {
	if len(msg) > 0 {
		msg = util.CapitalizeMessage(msg)
	}
	return &ormapi.Result{Message: msg}
}

func MsgErr(err error) *ormapi.Result {
	return &ormapi.Result{Message: err.Error()}
}

func ctrlErr(c echo.Context, err error) error {
	msg := "controller connect error, " + err.Error()
	return c.JSON(http.StatusBadRequest, Msg(msg))
}

func dbErr(err error) error {
	return fmt.Errorf("database error, %s", err.Error())
}

func bindErr(c echo.Context, err error) error {
	var code int
	var msg string
	if e, ok := err.(*echo.HTTPError); ok {
		code = e.Code
		msg = fmt.Sprintf("%v", e.Message)
	} else {
		code = http.StatusBadRequest
		msg = err.Error()
	}
	return c.JSON(code, Msg("Invalid POST data, "+msg))
}

func setReply(c echo.Context, err error, data interface{}) error {
	code := http.StatusOK
	if err != nil {
		switch err {
		case echo.ErrForbidden:
			code = http.StatusForbidden
		case echo.ErrNotFound:
			code = http.StatusNotFound
		default:
			code = http.StatusBadRequest
		}
		// set error on context so it can be easily retrieved for audit log
		c.Set(echoContextError, err)
	}
	if ws := GetWs(c); ws != nil {
		wsPayload := ormapi.WSStreamPayload{
			Code: code,
		}
		if err != nil {
			wsPayload.Data = MsgErr(err)
		} else if data != nil {
			wsPayload.Data = data
		}
		out, err := json.Marshal(wsPayload)
		if err == nil {
			LogWsResponse(c, string(out))
		}
		return ws.WriteJSON(wsPayload)
	}
	if err != nil {
		// If error is HTTPError, pull out the message to prevent redundant status code info
		if e, ok := err.(*echo.HTTPError); ok {
			err = fmt.Errorf("%v", e.Message)
			code = e.Code
		}
		return c.JSON(code, MsgErr(err))
	}
	return c.JSON(code, data)
}

// streamReply funcs used by alldata always send back just a status
// message, never an error - even if an error was generated. So they
// never use payload.Result, which is used to convey an error.
func streamReply(c echo.Context, desc string, err error, hadErr *bool) {
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

func streamErr(c echo.Context, msg string) {
	payload := ormapi.StreamPayload{
		Result: &ormapi.Result{
			Message: msg,
		},
	}
	json.NewEncoder(c.Response()).Encode(payload)
	c.Response().Flush()
}
