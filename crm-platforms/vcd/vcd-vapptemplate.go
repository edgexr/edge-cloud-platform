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

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"

	"github.com/vmware/go-vcloud-director/v2/govcd"
)

const TemplateNotFoundError string = "Template Not Found"

type OvfParams struct {
	ImageBaseFileName string
	DiskSizeInBytes   string
	OSType            string
}

var vcdDirectUser string = "vcdDirect"

var OvfTemplate = `<?xml version='1.0' encoding='UTF-8'?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:vmw="http://www.vmware.com/schema/ovf" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData">
  <References>
    <File ovf:id="file1" ovf:href="{{.ImageBaseFileName}}.vmdk"/>
  </References>
  <DiskSection>
    <Info>List of the virtual disks</Info>
    <Disk ovf:capacityAllocationUnits="byte" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized" ovf:diskId="vmdisk1" ovf:capacity="{{.DiskSizeInBytes}}" ovf:fileRef="file1"/>
  </DiskSection>
  <VirtualSystem ovf:id="{{.ImageBaseFileName}}">
    <Info>A Virtual system</Info>
    <Name>{{.ImageBaseFileName}}</Name>
    <OperatingSystemSection ovf:id="94" vmw:osType="{{.OSType}}">
      <Info>The operating system installed</Info>
      <Description></Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemType>vmx-14</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>2 virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
        <vmw:CoresPerSocket ovf:required="false">1</vmw:CoresPerSocket>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>4096MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>4096</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 1</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogicsas</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="slotInfo.pciSlotNumber" vmw:value="192"/>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SATA Controller</rasd:Description>
        <rasd:ElementName>SATA Controller 1</rasd:ElementName>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:ResourceSubType>vmware.sata.ahci</rasd:ResourceSubType>
        <rasd:ResourceType>20</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="slotInfo.pciSlotNumber" vmw:value="33"/>
      </Item>
      <Item>
      <rasd:Description>USB Controller (XHCI)</rasd:Description>
      <rasd:ElementName>USB controller</rasd:ElementName>
      <rasd:InstanceID>5</rasd:InstanceID>
      <rasd:ResourceSubType>vmware.usb.xhci</rasd:ResourceSubType>
      <rasd:ResourceType>23</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>6</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
        <rasd:ElementName>CD/DVD Drive 1</rasd:ElementName>
        <rasd:InstanceID>7</rasd:InstanceID>
        <rasd:Parent>4</rasd:Parent>
        <rasd:ResourceSubType>vmware.cdrom.remotepassthrough</rasd:ResourceSubType>
        <rasd:ResourceType>15</rasd:ResourceType>
      </Item>
      <Item ovf:required="false">
        <rasd:ElementName>Video card</rasd:ElementName>
        <rasd:InstanceID>8</rasd:InstanceID>
        <rasd:ResourceType>24</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="numDisplays" vmw:value="1"/>
        <vmw:Config ovf:required="false" vmw:key="graphicsMemorySizeInKB" vmw:value="262144"/>
        <vmw:Config ovf:required="false" vmw:key="use3dRenderer" vmw:value="automatic"/>
        <vmw:Config ovf:required="false" vmw:key="enable3DSupport" vmw:value="false"/>
        <vmw:Config ovf:required="false" vmw:key="useAutoDetect" vmw:value="false"/>
        <vmw:Config ovf:required="false" vmw:key="videoRamSizeInKB" vmw:value="4096"/>
      </Item>
      <vmw:Config ovf:required="false" vmw:key="flags.vbsEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="cpuHotAddEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="nestedHVEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="virtualSMCPresent" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="flags.vvtdEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="cpuHotRemoveEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="memoryHotAddEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="false"/>
      <vmw:Config ovf:required="false" vmw:key="firmware" vmw:value="bios"/>
      <vmw:Config ovf:required="false" vmw:key="virtualICH7MPresent" vmw:value="false"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
`

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

	return nil, fmt.Errorf("%s - %s", TemplateNotFoundError, tmplName)
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

// AddImageIfNotPresent works as follows:
// 1) if the template is already in the VCD catalog, quit as there is nothing to do
// 2) if the VMDK is not in Artifactory, the qcow2 is downloaded and VMDK generated and uploaded back to Artifactory
// 3) regardless as to whether the VMDK had to be generated, the OVF is always regenerated in case something changed for VM images.  This is very fast
// 4) A token is generated and used to direct the VCD to import the OVF and corresponding VMDK from Artifactory
func (v *VcdPlatform) AddImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddImageIfNotPresent", "imageInfo", imageInfo)

	artifactoryVmdkPath := strings.TrimSuffix(imageInfo.ImagePath, filepath.Ext(imageInfo.ImagePath)) + ".vmdk"
	artifactoryOvfPath := strings.TrimSuffix(imageInfo.ImagePath, filepath.Ext(imageInfo.ImagePath)) + ".ovf"
	ovfExistsInArtifactory := false
	u, err := url.Parse(imageInfo.ImagePath)
	if err != nil {
		return fmt.Errorf("unable to parse app image path - %v", err)
	}
	ps := strings.Split(u.Path, "/")
	if len(ps) == 0 {
		return fmt.Errorf("Unexpected appimage path")
	}
	artifactoryHost := u.Host
	artifactoryPathMinusFile := u.Scheme + "://" + u.Host + strings.Join(ps[:len(ps)-1], "/") + "/"

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	// first see if this template already exists within our catalog
	_, err = v.FindTemplate(ctx, imageInfo.LocalImageName, vcdClient)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Found existing image template: %s", imageInfo.LocalImageName))
		return nil
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "FindTemplate failed", "err", err)
		if !strings.Contains(err.Error(), TemplateNotFoundError) {
			return fmt.Errorf("unexpected error finding template %s - %v", imageInfo.LocalImageName, err)
		}
	}

	filesToCleanup := []string{}
	filesToUpload := []string{}

	defer func() {
		for _, file := range filesToCleanup {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete file", "file", file)
			if delerr := cloudcommon.DeleteFile(file); delerr != nil {
				if !os.IsNotExist(delerr) {
					log.SpanLog(ctx, log.DebugLevelInfra, "delete file failed", "file", file, "error", delerr)
				}
			}
		}
	}()

	diskSize := vmlayer.MINIMUM_DISK_SIZE
	if imageInfo.Flavor != "" {
		flavor, err := v.GetFlavor(ctx, imageInfo.Flavor)
		if err != nil {
			return err
		}
		diskSize = flavor.Disk
	}

	// we generate a VMDK only if it is not there. We always regenerate the OVF in case the OS type changed
	log.SpanLog(ctx, log.DebugLevelInfra, "Will generate VMDK if not present", "artifactoryVmdkPath", artifactoryVmdkPath)
	_, _, err = infracommon.GetUrlInfo(ctx, v.vmProperties.CommonPf.PlatformConfig.AccessApi, artifactoryVmdkPath)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "VMDK already in artifactory", "artifactoryVmdkPath", artifactoryVmdkPath)
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "VMDK not yet in artifactory", "artifactoryVmdkPath", artifactoryVmdkPath)
		// need to download the qcow, convert to vmdk and then import to either VCD or Artifactory
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Downloading VM Image: %s", imageInfo.LocalImageName))
		fileWithPath, err := vmlayer.DownloadVMImage(ctx, v.vmProperties.CommonPf.PlatformConfig.AccessApi, imageInfo.LocalImageName, imageInfo.ImagePath, imageInfo.Md5sum)
		filesToCleanup = append(filesToCleanup, fileWithPath)
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
		if imageInfo.ImageType == edgeproto.ImageType_IMAGE_TYPE_QCOW {
			updateCallback(edgeproto.UpdateTask, "Converting Image to VMDK")
			vmdkFile, err := vmlayer.ConvertQcowToVmdk(ctx, fileWithPath, diskSize)
			filesToCleanup = append(filesToCleanup, vmdkFile)
			if err != nil {
				return err
			}
			filesToUpload = append(filesToUpload, vmdkFile)
		}
	}

	// check if OVF exists
	_, _, err = infracommon.GetUrlInfo(ctx, v.vmProperties.CommonPf.PlatformConfig.AccessApi, artifactoryOvfPath)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "OVF already in artifactory", "artifactoryOvfPath", artifactoryOvfPath)
		ovfExistsInArtifactory = true
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "OVF not yet in artifactory", "artifactoryOvfPath", artifactoryOvfPath)
	}

	// generate the OVF always if this a VM image, or if it does not already exist for platform images
	if !ovfExistsInArtifactory || imageInfo.ImageCategory == infracommon.ImageCategoryVmApp {
		baseFileName, err := cloudcommon.GetFileName(imageInfo.ImagePath)
		if err != nil {
			return nil
		}
		mappedOs, err := vmlayer.GetVmwareMappedOsType(imageInfo.OsType)
		if err != nil {
			return err
		}
		ovfParams := OvfParams{
			ImageBaseFileName: baseFileName,
			DiskSizeInBytes:   fmt.Sprintf("%d", diskSize*1024*1024*1024),
			OSType:            mappedOs,
		}
		ovfBuf, err := infracommon.ExecTemplate("vmwareOvf", OvfTemplate, ovfParams)
		if err != nil {
			return err
		}
		ovfFile := vmlayer.FileDownloadDir + baseFileName + ".ovf"
		log.SpanLog(ctx, log.DebugLevelInfra, "Creating OVF file", "ovfFile", ovfFile, "ovfParams", ovfParams)
		err = ioutil.WriteFile(ovfFile, ovfBuf.Bytes(), 0644)
		filesToCleanup = append(filesToCleanup, ovfFile)
		if err != nil {
			return fmt.Errorf("unable to write OVF file %s: %s", ovfFile, err.Error())
		}
		filesToUpload = append(filesToUpload, ovfFile)
	}

	for _, f := range filesToUpload {
		basepath := filepath.Base(f)
		uploadPath := artifactoryPathMinusFile + basepath
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Uploading: %s to Artifactory", basepath))
		log.SpanLog(ctx, log.DebugLevelInfra, "Uploading to Artifactory", "file", f, "uploadPath", uploadPath)
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
		// artifactory does not replace files on PUT (although it should) so delete it first if it is there
		resp, err := cloudcommon.SendHTTPReq(ctx, "DELETE", uploadPath, v.vmProperties.CommonPf.PlatformConfig.AccessApi, cloudcommon.NoCreds, &reqConfig, nil)
		log.SpanLog(ctx, log.DebugLevelInfra, "Existing file deleted if present", "err", err)
		if err == nil {
			resp.Body.Close()
		}
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
		resp, err = cloudcommon.SendHTTPReq(ctx, "PUT", uploadPath, v.vmProperties.CommonPf.PlatformConfig.AccessApi, cloudcommon.NoCreds, &reqConfig, body)
		log.SpanLog(ctx, log.DebugLevelInfra, "File uploaded", "file", file, "resp", resp, "err", err)
		if err != nil {
			return fmt.Errorf("Error uploading %s to artifactory - %v", f, err)
		}
		defer resp.Body.Close()
	}

	if !v.GetTemplateArtifactoryImportEnabled() {
		return fmt.Errorf("Template not found in catalog and import is disabled.  Please upload ovf from \"%s\" manually to catalog and name as \"%s\" and try again", artifactoryOvfPath, imageInfo.LocalImageName)
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
	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Importing OVF to VCD for Image: %s", imageInfo.LocalImageName))
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

func (v *VcdPlatform) DeleteImage(ctx context.Context, folder, image string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage", "image", image)
	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	err := v.DeleteTemplate(ctx, image, vcdClient)
	if err != nil {
		if strings.Contains(err.Error(), govcd.ErrorEntityNotFound.Error()) {
			log.SpanLog(ctx, log.DebugLevelInfra, "image already deleted", "image", image)
			return nil
		} else {
			return fmt.Errorf("DeleteImage: %s failed - %v", image, err)
		}
	}
	return nil
}
