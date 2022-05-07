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

package edgeproto

import (
	fmt "fmt"

	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
)

var OperatorCodeKeyTag = "operatorcode"

type OperatorCodeKey string

func (m OperatorCodeKey) GetKeyString() string {
	return string(m)
}

func (m *OperatorCodeKey) Matches(o *OperatorCodeKey) bool {
	return string(*m) == string(*o)
}

func (m OperatorCodeKey) NotFoundError() error {
	return fmt.Errorf("OperatorCode key %s not found", m.GetKeyString())
}

func (m OperatorCodeKey) ExistsError() error {
	return fmt.Errorf("OperatorCode key %s already exists", m.GetKeyString())
}

func (m OperatorCodeKey) GetTags() map[string]string {
	return map[string]string{
		OperatorCodeKeyTag: string(m),
	}
}

func (m *OperatorCode) GetObjKey() objstore.ObjKey {
	return m.GetKey()
}

func (m *OperatorCode) GetKey() *OperatorCodeKey {
	key := m.GetKeyVal()
	return &key
}

func (m *OperatorCode) GetKeyVal() OperatorCodeKey {
	return OperatorCodeKey(m.Code)
}

func (m *OperatorCode) SetKey(key *OperatorCodeKey) {
	m.Code = string(*key)
}

func CmpSortOperatorCode(a OperatorCode, b OperatorCode) bool {
	return a.GetKey().GetKeyString() < b.GetKey().GetKeyString()
}

func OperatorCodeKeyStringParse(str string, obj *OperatorCode) {
	obj.Code = str
}
