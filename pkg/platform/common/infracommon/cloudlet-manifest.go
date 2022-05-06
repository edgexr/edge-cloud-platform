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

package infracommon

import (
	"fmt"

	yaml "github.com/mobiledgex/yaml/v2"
)

type ManifestContentType string

const ManifestTypeNone ManifestContentType = "none"
const ManifestTypeURL ManifestContentType = "url"
const ManifestTypeCode ManifestContentType = "code"
const ManifestTypeCommand = "command"

type ManifestContentSubType string

const ManifestSubTypeNone ManifestContentSubType = "none"
const ManifestSubTypeBash ManifestContentSubType = "bash"
const ManifestSubTypePython ManifestContentSubType = "python"
const ManifestSubTypeYaml ManifestContentSubType = "yaml"

type CloudletManifestItem struct {
	Id             uint32
	Title          string
	ContentType    ManifestContentType
	ContentSubType ManifestContentSubType
	Content        string
	SubManifests   []CloudletManifestItem
}
type CloudletManifest struct {
	ManifestItems []CloudletManifestItem
}

func (m *CloudletManifest) AddItem(title string, contentType ManifestContentType, contentSubType ManifestContentSubType, content string) {
	item := CloudletManifestItem{
		Title:          title,
		ContentType:    contentType,
		ContentSubType: contentSubType,
		Content:        content,
	}
	item.Id = uint32(len(m.ManifestItems) + 1)
	m.ManifestItems = append(m.ManifestItems, item)
}

func (m *CloudletManifest) AddSubItem(title string, contentType ManifestContentType, contentSubType ManifestContentSubType, content string) {
	if len(m.ManifestItems) == 0 {
		// add an empty item. Alternatively we could throw and error but then we have
		// to add a lot of error checking in the code that runs this
		m.AddItem("", ManifestTypeNone, ManifestSubTypeNone, "")
	}
	subItem := CloudletManifestItem{
		Title:          title,
		ContentType:    contentType,
		ContentSubType: contentSubType,
		Content:        content,
	}
	manifestIdx := len(m.ManifestItems) - 1
	subItem.Id = uint32(len(m.ManifestItems[manifestIdx].SubManifests) + 1)
	m.ManifestItems[manifestIdx].SubManifests = append(m.ManifestItems[manifestIdx].SubManifests, subItem)
}

func (m *CloudletManifest) ToString() (string, error) {
	out, err := yaml.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("Failed to marshal manifest: %v", err)
	}
	return string(out), nil
}
