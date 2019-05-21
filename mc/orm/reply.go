package orm

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

type M map[string]interface{}

func Msg(msg string) *ormapi.Result {
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
	msg := "Invalid POST data, " + err.Error()
	return c.JSON(http.StatusBadRequest, Msg(msg))
}

func setReply(c echo.Context, err error, successReply interface{}) error {
	if err == echo.ErrForbidden {
		return err
	}
	if err != nil {
		return c.JSON(http.StatusBadRequest, MsgErr(err))
	}
	return c.JSON(http.StatusOK, successReply)
}

func streamReply(c echo.Context, desc string, err error) {
	res := "ok"
	code := 0
	if err == echo.ErrForbidden {
		res = "forbidden"
		code = http.StatusForbidden
	} else if err != nil {
		res = err.Error()
		code = http.StatusBadRequest
	}
	streamReplyMsg(c, desc, res, code)
}

func streamReplyMsg(c echo.Context, desc, res string, code int) {
	msg := ormapi.Result{
		Message: fmt.Sprintf("%s: %s", desc, res),
		Code:    code,
	}
	json.NewEncoder(c.Response()).Encode(msg)
	c.Response().Flush()
}
