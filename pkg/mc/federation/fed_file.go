package federation

import (
	"fmt"

	"github.com/labstack/echo/v4"
)

func (p *PartnerApi) UploadFile(c echo.Context, fedCtxId FederationContextId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) RemoveFile(c echo.Context, fedCtxId FederationContextId, fileId FileId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) ViewFile(c echo.Context, fedCtxId FederationContextId, fileId FileId) error {
	return fmt.Errorf("not implemented yet")
}
