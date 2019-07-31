package orm

import (
	"context"

	"github.com/labstack/echo"
)

type EchoContext struct {
	echo.Context
	ctx context.Context
}

func NewEchoContext(c echo.Context, ctx context.Context) *EchoContext {
	ec := EchoContext{
		Context: c,
		ctx:     ctx,
	}
	return &ec
}

func GetContext(c echo.Context) context.Context {
	ec, ok := c.(*EchoContext)
	if !ok {
		panic("auditlog.go logger func should have wrapped echo.Context with EchoContext")
	}
	return ec.ctx
}
