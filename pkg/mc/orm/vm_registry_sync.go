package orm

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/labstack/echo/v4"
)

func VmRegistryNewSync() *AppStoreSync {
	vmsync := AppStoreNewSync("vmregistry")
	vmsync.syncObjects = vmsync.syncVmRegistry
	vmsync.needsSync = true
	return vmsync
}

func (s *AppStoreSync) syncVmRegistry(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelApi, "vm-registry sync")

	// ensure main admin access api key
	err := vmRegistryEnsureApiKey(ctx, Superuser)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	// get main access apikey for username
	auth, err := getVmRegAdminAuth(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}

	orgsT, err := GetAllOrgs(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	for _, org := range orgsT {
		if org.Type == OrgTypeOperator {
			continue
		}
		err = vmRegistryEnsurePullKey(ctx, org.Name, auth.Username)
		if err != nil {
			s.syncErr(ctx, err)
		}
	}
}

func VmRegistryResync(c echo.Context) error {
	err := AdminAccessCheck(c)
	if err != nil {
		return err
	}
	vmRegistrySync.NeedsSync()
	vmRegistrySync.wakeup()
	return err
}
