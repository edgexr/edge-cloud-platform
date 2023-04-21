package orm

import (
	"context"
	"sync"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var CorsHandlerFunc = corsDisabledHandler
var CorsHandlerMux sync.Mutex

func corsDisabledHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return next
}

// Wrap the cors middlware handler in our own so that we
// can update the config dynamically.
func CorsHandler(next echo.HandlerFunc) echo.HandlerFunc {
	CorsHandlerMux.Lock()
	mwfunc := CorsHandlerFunc
	CorsHandlerMux.Unlock()
	return mwfunc(next)
}

func UpdateCorsConfig(ctx context.Context, config *ormapi.Config) {
	log.SpanLog(ctx, log.DebugLevelApi, "Updating CORS config", "config", config)
	if !config.CorsEnable {
		CorsHandlerMux.Lock()
		CorsHandlerFunc = corsDisabledHandler
		CorsHandlerMux.Unlock()
		return
	}
	corsConfig := middleware.DefaultCORSConfig
	corsConfig.AllowOrigins = config.CorsAllowedOrigins
	corsConfig.AllowHeaders = config.CorsAllowedHeaders
	corsConfig.AllowCredentials = config.CorsAllowCredentials

	mwfunc := middleware.CORSWithConfig(corsConfig)
	CorsHandlerMux.Lock()
	defer CorsHandlerMux.Unlock()
	CorsHandlerFunc = mwfunc
}
