package orm

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func authzCreateApp(ctx context.Context, region, username string, obj *edgeproto.App, resource, action string) error {
	if err := checkImagePath(ctx, obj); err != nil {
		return err
	}
	if !authorized(ctx, username, obj.Key.DeveloperKey.Name, resource, action) {
		return echo.ErrForbidden
	}
	return nil
}

func authzUpdateApp(ctx context.Context, region, username string, obj *edgeproto.App, resource, action string) error {
	if err := checkImagePath(ctx, obj); err != nil {
		return err
	}
	if !authorized(ctx, username, obj.Key.DeveloperKey.Name, resource, action) {
		return echo.ErrForbidden
	}
	return nil
}

// checkImagePath checks that for a mobiledgex image path, the App's org matches
// the image path's org. This assumes someone cannot spoof a .mobiledgex.net DNS
// address.
func checkImagePath(ctx context.Context, obj *edgeproto.App) error {
	if obj.ImagePath == "" {
		return nil
	}
	u, err := url.Parse(obj.ImagePath)
	if err != nil {
		return fmt.Errorf("Failed to parse ImagePath, %v", err)
	}
	dns := ".mobiledgex.net"
	if !strings.HasSuffix(u.Host, ".mobiledgex.net") {
		return nil
	}
	// user could put an IP instead of DNS entry to bypass above check,
	// but we look up registry perms from Vault, and we shouldn't put
	// IP addresses into Vault for registries.
	artPrefix := "artifactory/" + ArtifactoryRepoPrefix
	path := strings.TrimLeft(u.Path, "/")
	if strings.HasPrefix(path, artPrefix) {
		// artifactory path
		path = strings.TrimPrefix(path, artPrefix)
	} else {
		// gitlab path starts with org name
	}
	pathNames := strings.Split(path, "/")
	if len(pathNames) == 0 {
		return fmt.Errorf("Empty URL path in ImagePath")
	}
	targetOrg := pathNames[0]

	lookup := ormapi.Organization{}
	lookup.Name = targetOrg
	db := loggedDB(ctx)
	err = db.Where(&lookup).First(&lookup).Error
	if err != nil {
		return err
	}
	if lookup.PublicImages {
		// all images in target org are public
		return nil
	}

	if strings.ToLower(targetOrg) != strings.ToLower(obj.Key.DeveloperKey.Name) {
		return fmt.Errorf("ImagePath for %s registry using organization '%s' does not match App developer name '%s', must match", dns, targetOrg, obj.Key.DeveloperKey.Name)
	}
	return nil
}
