// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orm

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/edgeproto"
)

func authzCreateApp(ctx context.Context, region, username string, obj *edgeproto.App, resource, action string) error {
	if err := checkImagePath(ctx, obj); err != nil {
		return err
	}
	return authorized(ctx, username, obj.Key.Organization, resource, action, withRequiresOrg(obj.Key.Organization))
}

func authzUpdateApp(ctx context.Context, region, username string, obj *edgeproto.App, resource, action string) error {
	if err := checkImagePath(ctx, obj); err != nil {
		return err
	}
	return authorized(ctx, username, obj.Key.Organization, resource, action)
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
	if u.Scheme == "" {
		// No scheme specified, causes host to be parsed as path.
		// Typical for docker URIs that leave out the http scheme.
		u, err = url.Parse("http://" + obj.ImagePath)
		if err != nil {
			return fmt.Errorf("Failed to parse http:// scheme prepended ImagePath, %v", err)
		}
	}
	if u.Host == "" {
		return fmt.Errorf("Unable to determine host from ImagePath %s", obj.ImagePath)
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
	if targetOrg == "" {
		return fmt.Errorf("Empty organization name in ImagePath")
	}

	lookup := ormapi.Organization{}
	lookup.Name = targetOrg
	db := loggedDB(ctx)
	res := db.Where(&lookup).First(&lookup)
	if res.RecordNotFound() {
		return fmt.Errorf("Organization %s from ImagePath not found", targetOrg)
	}
	if err != nil {
		return err
	}
	if lookup.PublicImages {
		// all images in target org are public
		return nil
	}

	if strings.ToLower(targetOrg) != strings.ToLower(obj.Key.Organization) {
		return fmt.Errorf("ImagePath for %s registry using organization '%s' does not match App developer name '%s', must match", dns, targetOrg, obj.Key.Organization)
	}
	return nil
}
