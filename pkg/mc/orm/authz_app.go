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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
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

func authzDeleteApp(ctx context.Context, region, username string, obj *edgeproto.App, resource, action string) error {
	fedApp, err := isProviderApp(ctx, obj)
	if err != nil {
		return err
	}
	if fedApp {
		return fmt.Errorf("Cannot delete App created via federation, use unsafe federation app delete instead")
	}
	return authorized(ctx, username, obj.Key.Organization, resource, action)
}

// checkImagePath checks that for a Edge Cloud image path, the App's org matches
// the image path's org. This assumes someone cannot spoof the DNS
// address.
func checkImagePath(ctx context.Context, obj *edgeproto.App) error {
	return checkImagePathStrings(ctx, obj.Key.Organization, obj.ImagePath)
}

func checkImagePathStrings(ctx context.Context, org, imagePath string) error {
	if imagePath == "" {
		return nil
	}
	u, err := url.Parse(imagePath)
	if err != nil {
		return fmt.Errorf("Failed to parse ImagePath, %v", err)
	}
	if u.Scheme == "" {
		// No scheme specified, causes host to be parsed as path.
		// Typical for docker URIs that leave out the http scheme.
		u, err = url.Parse("http://" + imagePath)
		if err != nil {
			return fmt.Errorf("Failed to parse http:// scheme prepended ImagePath, %v", err)
		}
	}
	if u.Host == "" {
		return fmt.Errorf("Unable to determine host from ImagePath %s", imagePath)
	}

	// all paths should be of the form
	// scheme://addr/pathprefix/org/image
	edgeCloudHosted := false
	pathPrefix := ""
	if serverConfig.GitlabAddr != "" {
		addr := util.TrimScheme(serverConfig.GitlabAddr)
		if strings.Contains(imagePath, addr) {
			edgeCloudHosted = true
		}
	}
	if serverConfig.ArtifactoryAddr != "" {
		addr := util.TrimScheme(serverConfig.ArtifactoryAddr)
		if strings.Contains(imagePath, addr) {
			edgeCloudHosted = true
			pathPrefix = "artifactory/" + ArtifactoryRepoPrefix
		}
	}
	if serverConfig.VmRegistryAddr != "" {
		addr := util.TrimScheme(serverConfig.VmRegistryAddr)
		if strings.Contains(imagePath, addr) {
			edgeCloudHosted = true
			pathPrefix = strings.TrimLeft(cloudcommon.VmRegPath, "/")
		}
	}
	if serverConfig.HarborAddr != "" {
		addr := util.TrimScheme(serverConfig.HarborAddr)
		if strings.Contains(imagePath, addr) {
			edgeCloudHosted = true
		}
	}
	if !edgeCloudHosted {
		return nil
	}
	// user could put an IP instead of DNS entry to bypass above check,
	// but we look up registry perms from Vault, and we shouldn't put
	// IP addresses into Vault for registries.
	path := strings.TrimLeft(u.Path, "/")
	path = strings.TrimPrefix(path, pathPrefix)
	path = strings.TrimPrefix(path, "/")
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

	if strings.ToLower(targetOrg) != strings.ToLower(org) {
		return fmt.Errorf("ImagePath %s for Edge Cloud hosted registry using organization '%s' does not match organization name '%s', must match", imagePath, targetOrg, org)
	}
	return nil
}

func authzDeleteAppInst(ctx context.Context, region, username string, obj *edgeproto.AppInst, resource, action string) error {
	fedAppInst, err := isProviderAppInst(ctx, obj)
	if err != nil {
		return err
	}
	if fedAppInst {
		return fmt.Errorf("Cannot delete AppInst created via federation, use unsafe federation appInst delete instead")
	}
	return authorized(ctx, username, obj.Key.AppKey.Organization, resource, action)
}
