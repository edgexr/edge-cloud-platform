package orm

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/util"
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
	internal error
}

func (s *HTTPError) Error() string {
	return s.Message
}

func newHTTPError(code int, err string) *HTTPError {
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

func dbErr(err error) error {
	return fmt.Errorf("database error, " + err.Error())
}

func bindErr(err error) error {
	return fmt.Errorf("invalid POST data, " + err.Error())
}

// setReply sets the reply data on a successful API call
func setReply(c echo.Context, data interface{}) error {
	return c.JSON(http.StatusOK, data)
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
