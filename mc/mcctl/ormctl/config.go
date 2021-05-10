package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

const ConfigGroup = "Config"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "UpdateConfig",
		Use:          "update",
		Short:        "Update master controller global configuration",
		OptionalArgs: "locknewaccounts notifyemailaddress, skipverifyemail, maxmetricsdatapoints, passwordmincracktimesec, adminpasswordmincracktimesec userapikeycreatelimit billingenable",
		ReqData:      &ormapi.Config{},
		Path:         "/auth/config/update",
	}, &ApiCommand{
		Name:  "ResetConfig",
		Use:   "reset",
		Short: "Reset master controller global configuration",
		Path:  "/auth/config/reset",
	}, &ApiCommand{
		Name:      "ShowConfig",
		Use:       "show",
		Short:     "Show master controller global configuration",
		ReplyData: &ormapi.Config{},
		Path:      "/auth/config/show",
	}, &ApiCommand{
		Name:      "ShowPublicConfig",
		Use:       "public",
		Short:     "Show publicly visible master controller global configuration",
		ReplyData: &ormapi.Config{},
		Path:      "/publicconfig",
	}, &ApiCommand{
		Name:      "MCVersion",
		Use:       "version",
		Short:     "Show master controller version",
		ReplyData: &ormapi.Version{},
		Path:      "/auth/config/version",
	}}
	AllApis.AddGroup(ConfigGroup, "Manage global configuration", cmds)
}
