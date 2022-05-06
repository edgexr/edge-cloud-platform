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

package ormctl

import (
	fmt "fmt"
	"strings"

	"github.com/edgexr/edge-cloud/util"
)

// ApiCommand defines the client interaction with the API. It is very
// similar to what would be found in a protobuf file, combining data from
// the service and messages.
// ReplyData should be a pointer to the type returned by the API call.
// For streaming APIs, ReplyData should be a pointer to the type streamed
// back, not an array of all streamed back objects.
type ApiCommand struct {
	Name                 string // client API func name
	Group                string // CLI group
	Use                  string // CLI command
	Short                string // short description
	RequiredArgs         string
	OptionalArgs         string
	AliasArgs            string
	SpecialArgs          *map[string]string
	Comments             map[string]string
	NoConfig             string
	PasswordArg          string
	CurrentPasswordArg   string
	VerifyPassword       bool
	ReqData              interface{}
	ReplyData            interface{}
	Path                 string
	ProtobufApi          bool
	StreamOut            bool
	StreamOutIncremental bool
	DataFlagOnly         bool
	IsUpdate             bool
	CliEmptyRequiredArgs string
	ShowFilter           bool
}

type ApiGroup struct {
	Name     string
	Desc     string
	Commands []*ApiCommand
}

type All struct {
	Groups   map[string]*ApiGroup
	Commands map[string]*ApiCommand
}

var AllApis = NewAll()

func NewAll() *All {
	all := &All{}
	all.Groups = make(map[string]*ApiGroup)
	all.Commands = make(map[string]*ApiCommand)
	return all
}

func (s *All) AddGroup(name, desc string, cmds []*ApiCommand) {
	if _, found := s.Groups[name]; found {
		panic(fmt.Errorf("Already a group named %s", name))
	}
	group := &ApiGroup{
		Name:     name,
		Desc:     desc,
		Commands: cmds,
	}
	s.Groups[group.Name] = group
	for _, cmd := range cmds {
		cmd.Group = name
		s.AddCommand(cmd)
	}
}

func (s *All) AddCommand(cmd *ApiCommand) {
	if cmd.Name == "" {
		panic(fmt.Errorf("command name not defined"))
	}
	if _, found := s.Commands[cmd.Name]; found {
		panic(fmt.Errorf("Already a command named %s", cmd.Name))
	}
	if err := cmd.Validate(); err != nil {
		panic(err.Error())
	}
	s.Commands[cmd.Name] = cmd
}

func (s *All) GetGroup(groupName string) *ApiGroup {
	return s.Groups[groupName]
}

func (s *All) GetCommand(name string) *ApiCommand {
	return s.Commands[name]
}

func MustGetCommand(name string) *ApiCommand {
	apiCmd := AllApis.GetCommand(name)
	if apiCmd == nil {
		panic(fmt.Errorf("command %s not found", name))
	}
	return apiCmd
}

func MustGetGroup(name string) *ApiGroup {
	apiGroup := AllApis.GetGroup(name)
	if apiGroup == nil {
		panic(fmt.Errorf("group %s not found", name))
	}
	return apiGroup
}

// Convert the comments map to use the aliased args
func aliasedComments(comments map[string]string, aliases []string) map[string]string {
	lookup := map[string]string{}
	aliasedComments := map[string]string{}
	for _, alias := range aliases {
		kv := strings.SplitN(alias, "=", 2)
		if len(kv) != 2 {
			continue
		}
		lookup[kv[1]] = kv[0]
	}
	for k, v := range comments {
		if alias, found := lookup[k]; found {
			aliasedComments[alias] = v
		} else {
			aliasedComments[k] = v
		}
	}
	return aliasedComments
}

func addRegionComment(comments map[string]string) map[string]string {
	comments["region"] = "Region name"
	return comments
}

func (s *ApiCommand) Validate() error {
	// make sure all arguments have valid help comment
	args := []string{}
	if str := strings.TrimSpace(s.RequiredArgs); str != "" {
		args = append(args, strings.Split(str, " ")...)
	}
	if str := strings.TrimSpace(s.OptionalArgs); str != "" {
		args = append(args, strings.Split(str, " ")...)
	}
	missingComments := []string{}
	for _, arg := range args {
		_, found := s.Comments[arg]
		if !found {
			missingComments = append(missingComments, arg)
		}
	}
	if len(missingComments) > 0 {
		return fmt.Errorf("Error, no comment found for command %s args %v, comments are %v, aliases are %v", s.Name, missingComments, s.Comments, s.AliasArgs)
	}
	aliasMap := make(map[string]string)
	for _, alias := range strings.Fields(s.AliasArgs) {
		kv := strings.SplitN(alias, "=", 2)
		if len(kv) != 2 {
			continue
		}
		aliasMap[kv[1]] = kv[0]
	}
	badArgs := []string{}
	for _, arg := range args {
		if alias, found := aliasMap[arg]; found {
			arg = alias
		}
		if !util.ValidCliArg(arg) {
			badArgs = append(badArgs, arg)
		}
	}
	if len(badArgs) > 0 {
		return fmt.Errorf("Error, bad format for command %s args %v, only lowercase letters and numbers allowed", s.Name, badArgs)
	}
	return nil
}
