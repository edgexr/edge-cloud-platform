package ormctl

import (
	fmt "fmt"
	"strings"
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
			delete(comments, k)
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
