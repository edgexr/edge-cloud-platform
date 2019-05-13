// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: debug.proto

/*
Package gencmd is a generated protocol buffer package.

It is generated from these files:
	debug.proto

It has these top-level messages:
	DebugLevels
	DebugResult
*/
package gencmd

import log "github.com/mobiledgex/edge-cloud/log"
import "strings"
import "strconv"
import "github.com/spf13/cobra"
import "context"
import "os"
import "text/tabwriter"
import "github.com/spf13/pflag"
import "errors"
import "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/cmdsup"
import "google.golang.org/grpc/status"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
var DebugApiCmd log.DebugApiClient
var DebugLevelsIn log.DebugLevels
var DebugLevelsFlagSet = pflag.NewFlagSet("DebugLevels", pflag.ExitOnError)
var DebugLevelsNoConfigFlagSet = pflag.NewFlagSet("DebugLevelsNoConfig", pflag.ExitOnError)
var DebugLevelsInLevels string
var DebugLevelStrings = []string{
	"etcd",
	"api",
	"notify",
	"dmedb",
	"dmereq",
	"locapi",
	"mexos",
	"metrics",
	"upgrade",
}

func DebugLevelsSlicer(in *log.DebugLevels) []string {
	s := make([]string, 0, 1)
	if in.Levels == nil {
		in.Levels = make([]log.DebugLevel, 1)
	}
	s = append(s, log.DebugLevel_name[int32(in.Levels[0])])
	return s
}

func DebugLevelsHeaderSlicer() []string {
	s := make([]string, 0, 1)
	s = append(s, "Levels")
	return s
}

func DebugLevelsWriteOutputArray(objs []*log.DebugLevels) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(DebugLevelsHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(DebugLevelsSlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func DebugLevelsWriteOutputOne(obj *log.DebugLevels) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(DebugLevelsHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(DebugLevelsSlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}
func DebugResultSlicer(in *log.DebugResult) []string {
	s := make([]string, 0, 2)
	s = append(s, in.Status)
	s = append(s, strconv.FormatUint(uint64(in.Code), 10))
	return s
}

func DebugResultHeaderSlicer() []string {
	s := make([]string, 0, 2)
	s = append(s, "Status")
	s = append(s, "Code")
	return s
}

func DebugResultWriteOutputArray(objs []*log.DebugResult) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(DebugResultHeaderSlicer(), "\t"))
		for _, obj := range objs {
			fmt.Fprintln(output, strings.Join(DebugResultSlicer(obj), "\t"))
		}
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(objs)
	}
}

func DebugResultWriteOutputOne(obj *log.DebugResult) {
	if cmdsup.OutputFormat == cmdsup.OutputFormatTable {
		output := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(output, strings.Join(DebugResultHeaderSlicer(), "\t"))
		fmt.Fprintln(output, strings.Join(DebugResultSlicer(obj), "\t"))
		output.Flush()
	} else {
		cmdsup.WriteOutputGeneric(obj)
	}
}

var EnableDebugLevelsCmd = &cobra.Command{
	Use: "EnableDebugLevels",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		err := parseDebugLevelsEnums()
		if err != nil {
			return fmt.Errorf("EnableDebugLevels failed: %s", err.Error())
		}
		return EnableDebugLevels(&DebugLevelsIn)
	},
}

func EnableDebugLevels(in *log.DebugLevels) error {
	if DebugApiCmd == nil {
		return fmt.Errorf("DebugApi client not initialized")
	}
	ctx := context.Background()
	obj, err := DebugApiCmd.EnableDebugLevels(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("EnableDebugLevels failed: %s", errstr)
	}
	DebugResultWriteOutputOne(obj)
	return nil
}

func EnableDebugLevelss(data []log.DebugLevels, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("EnableDebugLevels %v\n", data[ii])
		myerr := EnableDebugLevels(&data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DisableDebugLevelsCmd = &cobra.Command{
	Use: "DisableDebugLevels",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		err := parseDebugLevelsEnums()
		if err != nil {
			return fmt.Errorf("DisableDebugLevels failed: %s", err.Error())
		}
		return DisableDebugLevels(&DebugLevelsIn)
	},
}

func DisableDebugLevels(in *log.DebugLevels) error {
	if DebugApiCmd == nil {
		return fmt.Errorf("DebugApi client not initialized")
	}
	ctx := context.Background()
	obj, err := DebugApiCmd.DisableDebugLevels(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("DisableDebugLevels failed: %s", errstr)
	}
	DebugResultWriteOutputOne(obj)
	return nil
}

func DisableDebugLevelss(data []log.DebugLevels, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("DisableDebugLevels %v\n", data[ii])
		myerr := DisableDebugLevels(&data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var ShowDebugLevelsCmd = &cobra.Command{
	Use: "ShowDebugLevels",
	RunE: func(cmd *cobra.Command, args []string) error {
		// if we got this far, usage has been met.
		cmd.SilenceUsage = true
		err := parseDebugLevelsEnums()
		if err != nil {
			return fmt.Errorf("ShowDebugLevels failed: %s", err.Error())
		}
		return ShowDebugLevels(&DebugLevelsIn)
	},
}

func ShowDebugLevels(in *log.DebugLevels) error {
	if DebugApiCmd == nil {
		return fmt.Errorf("DebugApi client not initialized")
	}
	ctx := context.Background()
	obj, err := DebugApiCmd.ShowDebugLevels(ctx, in)
	if err != nil {
		errstr := err.Error()
		st, ok := status.FromError(err)
		if ok {
			errstr = st.Message()
		}
		return fmt.Errorf("ShowDebugLevels failed: %s", errstr)
	}
	DebugLevelsWriteOutputOne(obj)
	return nil
}

func ShowDebugLevelss(data []log.DebugLevels, err *error) {
	if *err != nil {
		return
	}
	for ii, _ := range data {
		fmt.Printf("ShowDebugLevels %v\n", data[ii])
		myerr := ShowDebugLevels(&data[ii])
		if myerr != nil {
			*err = myerr
			break
		}
	}
}

var DebugApiCmds = []*cobra.Command{
	EnableDebugLevelsCmd,
	DisableDebugLevelsCmd,
	ShowDebugLevelsCmd,
}

func init() {
	EnableDebugLevelsCmd.Flags().AddFlagSet(DebugLevelsFlagSet)
	DisableDebugLevelsCmd.Flags().AddFlagSet(DebugLevelsFlagSet)
	ShowDebugLevelsCmd.Flags().AddFlagSet(DebugLevelsFlagSet)
}

func DebugApiAllowNoConfig() {
	EnableDebugLevelsCmd.Flags().AddFlagSet(DebugLevelsNoConfigFlagSet)
	DisableDebugLevelsCmd.Flags().AddFlagSet(DebugLevelsNoConfigFlagSet)
	ShowDebugLevelsCmd.Flags().AddFlagSet(DebugLevelsNoConfigFlagSet)
}

func parseDebugLevelsEnums() error {
	if DebugLevelsInLevels != "" {
		for _, str := range strings.Split(DebugLevelsInLevels, ",") {
			switch str {
			case "etcd":
				DebugLevelsIn.Levels = append(DebugLevelsIn.Levels, log.DebugLevel(0))
			case "api":
				DebugLevelsIn.Levels = append(DebugLevelsIn.Levels, log.DebugLevel(1))
			case "notify":
				DebugLevelsIn.Levels = append(DebugLevelsIn.Levels, log.DebugLevel(2))
			case "dmedb":
				DebugLevelsIn.Levels = append(DebugLevelsIn.Levels, log.DebugLevel(3))
			case "dmereq":
				DebugLevelsIn.Levels = append(DebugLevelsIn.Levels, log.DebugLevel(4))
			case "locapi":
				DebugLevelsIn.Levels = append(DebugLevelsIn.Levels, log.DebugLevel(5))
			case "mexos":
				DebugLevelsIn.Levels = append(DebugLevelsIn.Levels, log.DebugLevel(6))
			case "metrics":
				DebugLevelsIn.Levels = append(DebugLevelsIn.Levels, log.DebugLevel(7))
			case "upgrade":
				DebugLevelsIn.Levels = append(DebugLevelsIn.Levels, log.DebugLevel(8))
			default:
				return errors.New("Invalid value for DebugLevelsInLevels")
			}
		}
	}
	return nil
}
