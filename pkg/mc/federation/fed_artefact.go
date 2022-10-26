package federation

import (
	"fmt"

	"github.com/labstack/echo/v4"
)

func (p *PartnerApi) UploadArtefact(c echo.Context, fedCtxId FederationContextId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) RemoveArtefact(c echo.Context, fedCtxId FederationContextId, artefactId ArtefactId) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) GetArtefact(c echo.Context, fedCtxId FederationContextId, artefactId ArtefactId) error {
	return fmt.Errorf("not implemented yet")
}
