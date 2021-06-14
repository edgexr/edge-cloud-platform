package vcd

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"

	"github.com/vmware/go-vcloud-director/v2/govcd"
)

// Return requested vdc template
func (v *VcdPlatform) FindTemplate(ctx context.Context, tmplName string, vcdClient *govcd.VCDClient) (*govcd.VAppTemplate, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "Find template", "Name", tmplName)
	tmpls, err := v.GetAllVdcTemplates(ctx, vcdClient)
	if err != nil {
		return nil, err
	}

	for _, tmpl := range tmpls {
		if tmpl.VAppTemplate.Name == tmplName {
			log.SpanLog(ctx, log.DebugLevelInfra, "Found template", "Name", tmplName)
			return tmpl, nil
		}
	}

	return nil, fmt.Errorf("template %s not found", tmplName)
}

func (v *VcdPlatform) ImportTemplateFromUrl(ctx context.Context, name, templUrl string, catalog *govcd.Catalog) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ImportTemplateFromUrl", "name", name, "templUrl", templUrl)
	err := catalog.UploadOvfUrl(templUrl, name, name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed UploadOvfUrl", "err", err)
		return fmt.Errorf("Failed to upload from URL - %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ImportTemplateFromUrl done")
	return nil
}

// Return all templates found as vdc resources from MEX_CATALOG
func (v *VcdPlatform) GetAllVdcTemplates(ctx context.Context, vcdClient *govcd.VCDClient) ([]*govcd.VAppTemplate, error) {

	var tmpls []*govcd.VAppTemplate
	org, err := v.GetOrg(ctx, vcdClient)
	if err != nil {
		return tmpls, err
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return tmpls, err
	}
	// Get our catalog MEX_CATALOG
	catName := v.GetCatalogName()
	if catName == "" {
		return tmpls, fmt.Errorf("MEX_CATALOG name not found")
	}

	cat, err := org.GetCatalogByName(catName, true)
	if err != nil {
		return tmpls, err
	}

	for _, r := range vdc.Vdc.ResourceEntities {
		for _, res := range r.ResourceEntity {
			if res.Type == "application/vnd.vmware.vcloud.vAppTemplate+xml" {
				if v.Verbose {
					log.SpanLog(ctx, log.DebugLevelInfra, "Found Vdc resource template", "Name", res.Name, "from Catalog", catName)
				}
				tmpl, err := cat.GetVappTemplateByHref(res.HREF)
				if err != nil {
					continue
				} else {
					tmpls = append(tmpls, tmpl)
				}
			}
		}
	}
	return tmpls, nil
}

func (v *VcdPlatform) AddImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddImageIfNotPresent", "imageInfo", imageInfo)

	artifactoryPathMinusFile := ""
	ovfFile := ""
	artifactoryHost := ""
	artifactoryOvfPath := ""

	u, err := url.Parse(imageInfo.ImagePath)
	if err != nil {
		return fmt.Errorf("unable to parse app image path - %v", err)
	}
	ps := strings.Split(u.Path, "/")
	if len(ps) == 0 {
		return fmt.Errorf("Unexpected appimage path")
	}
	artifactoryHost = u.Host
	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	_, err = v.FindTemplate(ctx, imageInfo.LocalImageName, vcdClient)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Found existing image template: %s", imageInfo.LocalImageName))
		return nil
	}

	filesToCleanup := []string{}
	filesToUpload := []string{}

	defer func() {
		for _, file := range filesToCleanup {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete file", "file", file)
			if delerr := infracommon.DeleteFile(file); delerr != nil {
				if !os.IsNotExist(delerr) {
					log.SpanLog(ctx, log.DebugLevelInfra, "delete file failed", "file", file, "error", delerr)
				}
			}
		}
	}()

	artifactoryOvfPath = strings.TrimSuffix(imageInfo.ImagePath, filepath.Ext(imageInfo.ImagePath)) + ".ovf"
	log.SpanLog(ctx, log.DebugLevelInfra, "Will generate OVF if not present", "artifactoryOvfPath", artifactoryOvfPath)
	_, _, err = infracommon.GetUrlInfo(ctx, v.vmProperties.CommonPf.PlatformConfig.AccessApi, artifactoryOvfPath)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "OVF already in artifactory", "artifactoryOvfPath", artifactoryOvfPath)
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "OVF not yet in artifactory", "artifactoryOvfPath", artifactoryOvfPath)
		// need to download the qcow, convert to ovf/vmdk and then import to either VCD or Artifactory
		diskSize := vmlayer.MINIMUM_DISK_SIZE
		if imageInfo.Flavor != "" {
			flavor, err := v.GetFlavor(ctx, imageInfo.Flavor)
			if err != nil {
				return err
			}
			diskSize = flavor.Disk
		}

		updateCallback(edgeproto.UpdateTask, "Downloading VM Image")
		fileWithPath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.PlatformConfig.AccessApi, imageInfo.LocalImageName, imageInfo.ImagePath, imageInfo.Md5sum)
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "downloaded file", "fileWithPath", fileWithPath)

		// as the download may take a long time, refresh the session by triggering an API call
		_, err = v.GetOrg(ctx, vcdClient)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "fail to get org", "err", err)
			return fmt.Errorf("Failed to get VCD org")
		}
		filesToCleanup = append(filesToCleanup, fileWithPath)
		vmdkFile := fileWithPath
		if imageInfo.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
			updateCallback(edgeproto.UpdateTask, "Converting Image to VMDK")
			vmdkFile, err = vmlayer.ConvertQcowToVmdk(ctx, fileWithPath, diskSize)
			filesToCleanup = append(filesToCleanup, vmdkFile)
			if err != nil {
				return err
			}
			filesToUpload = append(filesToUpload, vmdkFile)
		}

		filenameNoExtension := strings.TrimSuffix(vmdkFile, filepath.Ext(vmdkFile))
		ovfFile = filenameNoExtension + ".ovf"

		imageFileBaseName := filepath.Base(filenameNoExtension)
		mappedOs, err := vmlayer.GetVmwareMappedOsType(imageInfo.OsType)
		if err != nil {
			return err
		}
		ovfParams := VmAppOvfParams{
			ImageBaseFileName: imageFileBaseName,
			DiskSizeInBytes:   fmt.Sprintf("%d", diskSize*1024*1024*1024),
			OSType:            mappedOs,
		}
		ovfBuf, err := infracommon.ExecTemplate("vmwareOvf", vmAppOvfTemplate, ovfParams)
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Creating OVF file", "ovfFile", ovfFile, "ovfParams", ovfParams)
		err = ioutil.WriteFile(ovfFile, ovfBuf.Bytes(), 0644)
		filesToCleanup = append(filesToCleanup, ovfFile)
		if err != nil {
			return fmt.Errorf("unable to write OVF file %s: %s", ovfFile, err.Error())
		}
		filesToUpload = append(filesToUpload, ovfFile)

		updateCallback(edgeproto.UpdateTask, "Uploading OVF to Artifactory")
		for _, f := range filesToUpload {
			artifactoryPathMinusFile = u.Scheme + "://" + u.Host + strings.Join(ps[:len(ps)-1], "/") + "/"
			uploadPath := artifactoryPathMinusFile + filepath.Base(f)
			log.SpanLog(ctx, log.DebugLevelInfra, "Uploading OVF to Artifactory", "uploadPath", uploadPath)
			file, err := os.Open(f)
			if err != nil {
				return fmt.Errorf("unable to open file: %s for upload - %v", f, err)
			}
			defer file.Close()
			fi, err := file.Stat()
			if err != nil {
				return fmt.Errorf("Could not stat file: %s - %v", f, err)
			}
			reqConfig := cloudcommon.RequestConfig{}
			size := fi.Size()
			timeout := cloudcommon.GetTimeout(int(size))
			if timeout > 0 {
				reqConfig.Timeout = timeout
				reqConfig.ResponseHeaderTimeout = timeout
				log.SpanLog(ctx, log.DebugLevelApi, "increased upload timeout", "file", f, "timeout", timeout.String())
			}
			body := bufio.NewReader(file)
			reqConfig.Headers = make(map[string]string)
			reqConfig.Headers["Content-Type"] = "application/octet-stream"
			resp, err := cloudcommon.SendHTTPReq(ctx, "PUT", uploadPath, v.vmProperties.CommonPf.PlatformConfig.AccessApi, cloudcommon.NoCreds, &reqConfig, body)
			log.SpanLog(ctx, log.DebugLevelInfra, "File uploaded", "file", file, "resp", resp, "err", err)
			if err != nil {
				return fmt.Errorf("Error uploading %s to artifactory - %v", f, err)
			}
			defer resp.Body.Close()
		}
	}
	// get a token that VCD can use to pull from the artifactory
	token, err := cloudcommon.GetAuthToken(ctx, artifactoryHost, v.vmProperties.CommonPf.PlatformConfig.AccessApi, vcdDirectUser)
	if err != nil {
		return fmt.Errorf("Fail to get artifactory token - %v", err)
	}
	cat, err := v.GetCatalog(ctx, v.GetCatalogName(), vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed retrieving catalog", "cat", v.GetCatalogName())
		return fmt.Errorf("failed to find upload catalog - %v", err)
	}
	artifactoryOvfPathWithToken := strings.Replace(artifactoryOvfPath, artifactoryHost, vcdDirectUser+":"+token+"@"+artifactoryHost, 1)
	updateCallback(edgeproto.UpdateTask, "Importing OVF to VCD from Artifactory")
	err = v.ImportTemplateFromUrl(ctx, imageInfo.LocalImageName, artifactoryOvfPathWithToken, cat)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to upload from url, deleting", "err", err)
		delerr := v.DeleteTemplate(ctx, imageInfo.LocalImageName, vcdClient)
		if delerr != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete failed", "delerr", delerr)
		}
		return err
	}
	return nil
}
