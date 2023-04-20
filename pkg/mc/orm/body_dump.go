// Copy of github.com/labstack/echo/v4/middleware/body_dump.go
// Modified for special handling for multipart/form-data

package orm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

type (
	Skipper func(c echo.Context) bool

	// BodyDumpConfig defines the config for BodyDump middleware.
	BodyDumpConfig struct {
		// Skipper defines a function to skip middleware.
		Skipper Skipper

		// Handler receives request and response payload.
		// Required.
		Handler BodyDumpHandler
	}

	// BodyDumpHandler receives the request and response payload.
	BodyDumpHandler func(echo.Context, []byte, []byte)

	bodyDumpResponseWriter struct {
		io.Writer
		http.ResponseWriter
	}
)

var (
	// DefaultBodyDumpConfig is the default BodyDump middleware config.
	DefaultBodyDumpConfig = BodyDumpConfig{
		Skipper: DefaultSkipper,
	}
)

const DumpLimit = 5000

func DefaultSkipper(echo.Context) bool {
	return false
}

// BodyDump returns a BodyDump middleware.
//
// BodyDump middleware captures the request and response payload and calls the
// registered handler.
func BodyDump(handler BodyDumpHandler) echo.MiddlewareFunc {
	c := DefaultBodyDumpConfig
	c.Handler = handler
	return BodyDumpWithConfig(c)
}

// BodyDumpWithConfig returns a BodyDump middleware with config.
// See: `BodyDump()`.
func BodyDumpWithConfig(config BodyDumpConfig) echo.MiddlewareFunc {
	// Defaults
	if config.Handler == nil {
		panic("echo: body-dump middleware requires a handler function")
	}
	if config.Skipper == nil {
		config.Skipper = DefaultBodyDumpConfig.Skipper
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			if config.Skipper(c) {
				return next(c)
			}

			// Request
			reqBody := []byte{}
			reqContentType := c.Request().Header.Get("Content-Type")
			if c.Request().Method != http.MethodGet {
				if strings.Contains(reqContentType, "application/json") || strings.Contains(reqContentType, "application/x-www-form-urlencoded") {
					if c.Request().Body != nil { // Read
						reqBody, _ = ioutil.ReadAll(c.Request().Body)
					}
					c.Request().Body = ioutil.NopCloser(bytes.NewBuffer(reqBody)) // Reset
				} else {
					reqBody = []byte(reqContentType + " data omitted")
				}
			}
			// Response
			resBody := new(bytes.Buffer)
			mw := io.MultiWriter(c.Response().Writer, resBody)
			writer := &bodyDumpResponseWriter{Writer: mw, ResponseWriter: c.Response().Writer}
			c.Response().Writer = writer

			if err = next(c); err != nil {
				c.Error(err)
			}

			if strings.Contains(reqContentType, "multipart/form-data") {
				out, err := json.Marshal(c.Request().PostForm)
				if err == nil {
					reqBody = out
				}
			}

			// Callback
			config.Handler(c, reqBody, resBody.Bytes())

			return
		}
	}
}

func (w *bodyDumpResponseWriter) WriteHeader(code int) {
	w.ResponseWriter.WriteHeader(code)
}

func (w *bodyDumpResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func (w *bodyDumpResponseWriter) Flush() {
	w.ResponseWriter.(http.Flusher).Flush()
}

func (w *bodyDumpResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}
