package ormctl

// Copies of exec commands, but with string output because
// mcctl opens the connection to the backend from the ExecRequest and
// returns the data as a string. These should only be used with
// the cliwrapper client.

func init() {
	genCliCmd := func(c *ApiCommand) *ApiCommand {
		cmd := *c
		cmd.Name += "Cli"
		var str string
		cmd.ReplyData = &str
		return &cmd
	}
	AllApis.AddCommand(genCliCmd(RunCommandCmd))
	AllApis.AddCommand(genCliCmd(ShowLogsCmd))
	AllApis.AddCommand(genCliCmd(AccessCloudletCmd))
}
