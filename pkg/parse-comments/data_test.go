// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parsecomments_test

import (
	"github.com/edgexr/edge-cloud-platform/pkg/parse-comments/data"
	dashes "github.com/edgexr/edge-cloud-platform/pkg/parse-comments/pkg-with-dashes"
)

type TopObject struct {
	// StringField comment
	// read only: true
	StringField string
	// IntField comment
	IntField       int
	NoCommentField string
	// Hidden field
	// hidden: true
	HiddenField int
	// FloatField comment
	FloatField float64
	// Map[string]string comment
	StringMapField map[string]string
	// Map comment
	MapField map[int]int
	// Array comment
	Array []string
	// Arrayed object comment
	ObjectArray []dashes.Timestamp
	// SubObject comment
	SubObject1 SubObject
	// PointerSubObject comment
	SubObjectPtr *SubObject
	// EmbeddedField comment
	SubObject
	// EmbeddedField from another package
	data.Data
}

type SubObject struct {
	// SubStringField comment
	SubStringField string
	// SubStringField2 comment
	SubStringField2 string
}

type OtherObject struct {
	// StringArrayField comment
	StringArrayField []string
	// Pointer Field comment
	StringPointer *string
	// External data
	Timestamp dashes.Timestamp
}
