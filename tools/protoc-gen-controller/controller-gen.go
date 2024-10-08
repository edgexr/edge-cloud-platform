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

package main

import (
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-platform/pkg/gensupport"
	"github.com/edgexr/edge-cloud-platform/tools/protogen"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/protoc-gen-gogo/descriptor"
	"github.com/gogo/protobuf/protoc-gen-gogo/generator"
)

type ControllerGen struct {
	*generator.Generator
	support gensupport.PluginSupport
}

func (s *ControllerGen) Name() string {
	return "ControllerGen"
}

func (s *ControllerGen) Init(g *generator.Generator) {
	s.Generator = g
	s.support.Init(g.Request)
}

func (s *ControllerGen) GenerateImports(file *generator.FileDescriptor) {
	// imports, if any
}

func (s *ControllerGen) Generate(file *generator.FileDescriptor) {
	s.support.InitFile()
	if !s.support.GenFile(*file.FileDescriptorProto.Name) {
		return
	}

	for _, desc := range file.Enums() {
		s.generateEnum(file, desc)
	}

	if s.Generator.Buffer.Len() != 0 {
		s.P(gensupport.AutoGenComment)
		gensupport.RunParseCheck(s.Generator, file)
	}
}

func (s *ControllerGen) generateEnum(file *generator.FileDescriptor, desc *generator.EnumDescriptor) {
	en := desc.EnumDescriptorProto
	if GetVersionHashOpt(en) {
		s.generateUpgradeFuncs(en)
	}
}

func (s *ControllerGen) generateUpgradeFuncs(enum *descriptor.EnumDescriptorProto) {
	s.P("type VersionUpgrade struct {")
	s.P("id int32")
	s.P("hash string")
	s.P("upgradeFunc VersionUpgradeFunc")
	s.P("name string")
	s.P("}")
	s.P()
	s.P("var ", enum.Name, "_UpgradeFuncs = []VersionUpgrade{")
	for _, e := range enum.Value {
		fnName := GetUpgradeFunc(e)
		fn := fnName
		if fnName == "" {
			fn = "nil"
		}
		hash := strconv.Quote(strings.TrimPrefix(*e.Name, "HASH_"))
		s.P("{", e.Number, ", ", hash, ", ", fn, ", ", strconv.Quote(fnName), "},")
	}
	s.P("}")
}

func GetVersionHashOpt(enum *descriptor.EnumDescriptorProto) bool {
	return proto.GetBoolExtension(enum.Options, protogen.E_VersionHash, false)
}

func GetUpgradeFunc(enumVal *descriptor.EnumValueDescriptorProto) string {
	return gensupport.GetStringExtension(enumVal.Options, protogen.E_UpgradeFunc, "")
}
