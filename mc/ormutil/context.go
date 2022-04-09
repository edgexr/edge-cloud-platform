package ormutil

import (
	"context"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"google.golang.org/grpc"
)

type RegionContext struct {
	Region    string
	Username  string
	Conn      *grpc.ClientConn
	SkipAuthz bool
	// Need database for federation handling
	Database *gorm.DB
}

type EchoContext struct {
	echo.Context
	ctx        context.Context
	ws         *websocket.Conn
	wsRequest  []byte
	wsResponse []string
	eventStart time.Time
}

func NewEchoContext(c echo.Context, ctx context.Context, eventStart time.Time) *EchoContext {
	ec := EchoContext{
		Context:    c,
		ctx:        ctx,
		eventStart: eventStart,
	}
	return &ec
}

func getEchoContext(c echo.Context) *EchoContext {
	ec, ok := c.(*EchoContext)
	if !ok {
		panic("auditlog.go logger func should have wrapped echo.Context with EchoContext")
	}
	return ec
}

func GetContext(c echo.Context) context.Context {
	return getEchoContext(c).ctx
}

func GetEventStart(c echo.Context) time.Time {
	return getEchoContext(c).eventStart
}

func SetWs(c echo.Context, ws *websocket.Conn) {
	ec, ok := c.(*EchoContext)
	if !ok {
		panic("auditlog.go logger func should have wrapped echo.Context with EchoContext")
	}
	ec.ws = ws
}

func GetWs(c echo.Context) *websocket.Conn {
	ec, ok := c.(*EchoContext)
	if !ok {
		panic("auditlog.go logger func should have wrapped echo.Context with EchoContext")
	}
	return ec.ws
}

func LogWsRequest(c echo.Context, data []byte) {
	ec, ok := c.(*EchoContext)
	if !ok {
		panic("auditlog.go logger func should have wrapped echo.Context with EchoContext")
	}
	ec.wsRequest = data
}

func LogWsResponse(c echo.Context, data string) {
	ec, ok := c.(*EchoContext)
	if !ok {
		panic("auditlog.go logger func should have wrapped echo.Context with EchoContext")
	}
	ec.wsResponse = append(ec.wsResponse, data)
}

func GetWsLogData(c echo.Context) ([]byte, []string) {
	ec, ok := c.(*EchoContext)
	if !ok {
		panic("auditlog.go logger func should have wrapped echo.Context with EchoContext")
	}
	return ec.wsRequest, ec.wsResponse
}
