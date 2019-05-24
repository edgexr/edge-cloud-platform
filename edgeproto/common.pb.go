// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: common.proto

package edgeproto

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"

import "github.com/mobiledgex/edge-cloud/util"
import "errors"
import "strconv"
import "encoding/json"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Liveness indicates if an object was created statically via an external API call, or dynamically via an internal algorithm.
type Liveness int32

const (
	// Unknown liveness
	Liveness_LIVENESS_UNKNOWN Liveness = 0
	// Object managed by external entity
	Liveness_LIVENESS_STATIC Liveness = 1
	// Object managed internally
	Liveness_LIVENESS_DYNAMIC Liveness = 2
)

var Liveness_name = map[int32]string{
	0: "LIVENESS_UNKNOWN",
	1: "LIVENESS_STATIC",
	2: "LIVENESS_DYNAMIC",
}
var Liveness_value = map[string]int32{
	"LIVENESS_UNKNOWN": 0,
	"LIVENESS_STATIC":  1,
	"LIVENESS_DYNAMIC": 2,
}

func (x Liveness) String() string {
	return proto.EnumName(Liveness_name, int32(x))
}
func (Liveness) EnumDescriptor() ([]byte, []int) { return fileDescriptorCommon, []int{0} }

// IpSupport indicates the type of public IP support provided by the Cloudlet. Static IP support indicates a set of static public IPs are available for use, and managed by the Controller. Dynamic indicates the Cloudlet uses a DHCP server to provide public IP addresses, and the controller has no control over which IPs are assigned.
type IpSupport int32

const (
	// Unknown IP support
	IpSupport_IP_SUPPORT_UNKNOWN IpSupport = 0
	// Static IP addresses are provided to and managed by Controller
	IpSupport_IP_SUPPORT_STATIC IpSupport = 1
	// IP addresses are dynamically provided by an Operator's DHCP server
	IpSupport_IP_SUPPORT_DYNAMIC IpSupport = 2
)

var IpSupport_name = map[int32]string{
	0: "IP_SUPPORT_UNKNOWN",
	1: "IP_SUPPORT_STATIC",
	2: "IP_SUPPORT_DYNAMIC",
}
var IpSupport_value = map[string]int32{
	"IP_SUPPORT_UNKNOWN": 0,
	"IP_SUPPORT_STATIC":  1,
	"IP_SUPPORT_DYNAMIC": 2,
}

func (x IpSupport) String() string {
	return proto.EnumName(IpSupport_name, int32(x))
}
func (IpSupport) EnumDescriptor() ([]byte, []int) { return fileDescriptorCommon, []int{1} }

type IpAccess int32

const (
	// Unknown IP access
	IpAccess_IP_ACCESS_UNKNOWN IpAccess = 0
	// Dedicated IP access
	IpAccess_IP_ACCESS_DEDICATED IpAccess = 1
	// Dedicated or shared (prefers dedicated) access
	IpAccess_IP_ACCESS_DEDICATED_OR_SHARED IpAccess = 2
	// Shared IP access
	IpAccess_IP_ACCESS_SHARED IpAccess = 3
)

var IpAccess_name = map[int32]string{
	0: "IP_ACCESS_UNKNOWN",
	1: "IP_ACCESS_DEDICATED",
	2: "IP_ACCESS_DEDICATED_OR_SHARED",
	3: "IP_ACCESS_SHARED",
}
var IpAccess_value = map[string]int32{
	"IP_ACCESS_UNKNOWN":             0,
	"IP_ACCESS_DEDICATED":           1,
	"IP_ACCESS_DEDICATED_OR_SHARED": 2,
	"IP_ACCESS_SHARED":              3,
}

func (x IpAccess) String() string {
	return proto.EnumName(IpAccess_name, int32(x))
}
func (IpAccess) EnumDescriptor() ([]byte, []int) { return fileDescriptorCommon, []int{2} }

// TrackedState is used to track the state of an object on a remote node,
// i.e. track the state of a ClusterInst object on the CRM (Cloudlet).
type TrackedState int32

const (
	// Unknown state
	TrackedState_TRACKED_STATE_UNKNOWN TrackedState = 0
	// Not present (does not exist)
	TrackedState_NOT_PRESENT TrackedState = 1
	// Create requested
	TrackedState_CREATE_REQUESTED TrackedState = 2
	// Creating
	TrackedState_CREATING TrackedState = 3
	// Create error
	TrackedState_CREATE_ERROR TrackedState = 4
	// Ready
	TrackedState_READY TrackedState = 5
	// Update requested
	TrackedState_UPDATE_REQUESTED TrackedState = 6
	// Updating
	TrackedState_UPDATING TrackedState = 7
	// Update error
	TrackedState_UPDATE_ERROR TrackedState = 8
	// Delete requested
	TrackedState_DELETE_REQUESTED TrackedState = 9
	// Deleting
	TrackedState_DELETING TrackedState = 10
	// Delete error
	TrackedState_DELETE_ERROR TrackedState = 11
	// Delete prepare (extra state used by controller to block other changes)
	TrackedState_DELETE_PREPARE TrackedState = 12
)

var TrackedState_name = map[int32]string{
	0:  "TRACKED_STATE_UNKNOWN",
	1:  "NOT_PRESENT",
	2:  "CREATE_REQUESTED",
	3:  "CREATING",
	4:  "CREATE_ERROR",
	5:  "READY",
	6:  "UPDATE_REQUESTED",
	7:  "UPDATING",
	8:  "UPDATE_ERROR",
	9:  "DELETE_REQUESTED",
	10: "DELETING",
	11: "DELETE_ERROR",
	12: "DELETE_PREPARE",
}
var TrackedState_value = map[string]int32{
	"TRACKED_STATE_UNKNOWN": 0,
	"NOT_PRESENT":           1,
	"CREATE_REQUESTED":      2,
	"CREATING":              3,
	"CREATE_ERROR":          4,
	"READY":                 5,
	"UPDATE_REQUESTED":      6,
	"UPDATING":              7,
	"UPDATE_ERROR":          8,
	"DELETE_REQUESTED":      9,
	"DELETING":              10,
	"DELETE_ERROR":          11,
	"DELETE_PREPARE":        12,
}

func (x TrackedState) String() string {
	return proto.EnumName(TrackedState_name, int32(x))
}
func (TrackedState) EnumDescriptor() ([]byte, []int) { return fileDescriptorCommon, []int{3} }

// CRMOverride can be applied to commands that issue requests to the CRM.
// It should only be used by administrators when bugs have caused the
// Controller and CRM to get out of sync. It allows commands from the
// Controller to ignore errors from the CRM, or ignore the CRM completely
// (messages will not be sent to CRM).
type CRMOverride int32

const (
	// No override
	CRMOverride_NO_OVERRIDE CRMOverride = 0
	// Ignore errors from CRM
	CRMOverride_IGNORE_CRM_ERRORS CRMOverride = 1
	// Ignore CRM completely (does not inform CRM of operation)
	CRMOverride_IGNORE_CRM CRMOverride = 2
	// Ignore Transient State (only admin should use if CRM crashed)
	CRMOverride_IGNORE_TRANSIENT_STATE CRMOverride = 3
	// Ignore CRM and Transient State
	CRMOverride_IGNORE_CRM_AND_TRANSIENT_STATE CRMOverride = 4
)

var CRMOverride_name = map[int32]string{
	0: "NO_OVERRIDE",
	1: "IGNORE_CRM_ERRORS",
	2: "IGNORE_CRM",
	3: "IGNORE_TRANSIENT_STATE",
	4: "IGNORE_CRM_AND_TRANSIENT_STATE",
}
var CRMOverride_value = map[string]int32{
	"NO_OVERRIDE":                    0,
	"IGNORE_CRM_ERRORS":              1,
	"IGNORE_CRM":                     2,
	"IGNORE_TRANSIENT_STATE":         3,
	"IGNORE_CRM_AND_TRANSIENT_STATE": 4,
}

func (x CRMOverride) String() string {
	return proto.EnumName(CRMOverride_name, int32(x))
}
func (CRMOverride) EnumDescriptor() ([]byte, []int) { return fileDescriptorCommon, []int{4} }

func init() {
	proto.RegisterEnum("edgeproto.Liveness", Liveness_name, Liveness_value)
	proto.RegisterEnum("edgeproto.IpSupport", IpSupport_name, IpSupport_value)
	proto.RegisterEnum("edgeproto.IpAccess", IpAccess_name, IpAccess_value)
	proto.RegisterEnum("edgeproto.TrackedState", TrackedState_name, TrackedState_value)
	proto.RegisterEnum("edgeproto.CRMOverride", CRMOverride_name, CRMOverride_value)
}

var LivenessStrings = []string{
	"LIVENESS_UNKNOWN",
	"LIVENESS_STATIC",
	"LIVENESS_DYNAMIC",
}

const (
	LivenessLIVENESS_UNKNOWN uint64 = 1 << 0
	LivenessLIVENESS_STATIC  uint64 = 1 << 1
	LivenessLIVENESS_DYNAMIC uint64 = 1 << 2
)

var Liveness_CamelName = map[int32]string{
	// LIVENESS_UNKNOWN -> LivenessUnknown
	0: "LivenessUnknown",
	// LIVENESS_STATIC -> LivenessStatic
	1: "LivenessStatic",
	// LIVENESS_DYNAMIC -> LivenessDynamic
	2: "LivenessDynamic",
}
var Liveness_CamelValue = map[string]int32{
	"LivenessUnknown": 0,
	"LivenessStatic":  1,
	"LivenessDynamic": 2,
}

func (e *Liveness) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, ok := Liveness_CamelValue[util.CamelCase(str)]
	if !ok {
		// may be enum value instead of string
		ival, err := strconv.Atoi(str)
		val = int32(ival)
		if err == nil {
			_, ok = Liveness_CamelName[val]
		}
	}
	if !ok {
		return errors.New(fmt.Sprintf("No enum value for %s", str))
	}
	*e = Liveness(val)
	return nil
}

func (e Liveness) MarshalYAML() (interface{}, error) {
	return proto.EnumName(Liveness_CamelName, int32(e)), nil
}

// custom JSON encoding/decoding
func (e *Liveness) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		val, ok := Liveness_CamelValue[util.CamelCase(str)]
		if !ok {
			// may be int value instead of enum name
			ival, err := strconv.Atoi(str)
			val = int32(ival)
			if err == nil {
				_, ok = Liveness_CamelName[val]
			}
		}
		if !ok {
			return errors.New(fmt.Sprintf("No enum value for %s", str))
		}
		*e = Liveness(val)
		return nil
	}
	var val int32
	err = json.Unmarshal(b, &val)
	if err == nil {
		*e = Liveness(val)
		return nil
	}
	return fmt.Errorf("No enum value for %v", b)
}

func (e Liveness) MarshalJSON() ([]byte, error) {
	str := proto.EnumName(Liveness_CamelName, int32(e))
	return []byte("\"" + str + "\""), nil
}

var IpSupportStrings = []string{
	"IP_SUPPORT_UNKNOWN",
	"IP_SUPPORT_STATIC",
	"IP_SUPPORT_DYNAMIC",
}

const (
	IpSupportIP_SUPPORT_UNKNOWN uint64 = 1 << 0
	IpSupportIP_SUPPORT_STATIC  uint64 = 1 << 1
	IpSupportIP_SUPPORT_DYNAMIC uint64 = 1 << 2
)

var IpSupport_CamelName = map[int32]string{
	// IP_SUPPORT_UNKNOWN -> IpSupportUnknown
	0: "IpSupportUnknown",
	// IP_SUPPORT_STATIC -> IpSupportStatic
	1: "IpSupportStatic",
	// IP_SUPPORT_DYNAMIC -> IpSupportDynamic
	2: "IpSupportDynamic",
}
var IpSupport_CamelValue = map[string]int32{
	"IpSupportUnknown": 0,
	"IpSupportStatic":  1,
	"IpSupportDynamic": 2,
}

func (e *IpSupport) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, ok := IpSupport_CamelValue[util.CamelCase(str)]
	if !ok {
		// may be enum value instead of string
		ival, err := strconv.Atoi(str)
		val = int32(ival)
		if err == nil {
			_, ok = IpSupport_CamelName[val]
		}
	}
	if !ok {
		return errors.New(fmt.Sprintf("No enum value for %s", str))
	}
	*e = IpSupport(val)
	return nil
}

func (e IpSupport) MarshalYAML() (interface{}, error) {
	return proto.EnumName(IpSupport_CamelName, int32(e)), nil
}

// custom JSON encoding/decoding
func (e *IpSupport) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		val, ok := IpSupport_CamelValue[util.CamelCase(str)]
		if !ok {
			// may be int value instead of enum name
			ival, err := strconv.Atoi(str)
			val = int32(ival)
			if err == nil {
				_, ok = IpSupport_CamelName[val]
			}
		}
		if !ok {
			return errors.New(fmt.Sprintf("No enum value for %s", str))
		}
		*e = IpSupport(val)
		return nil
	}
	var val int32
	err = json.Unmarshal(b, &val)
	if err == nil {
		*e = IpSupport(val)
		return nil
	}
	return fmt.Errorf("No enum value for %v", b)
}

func (e IpSupport) MarshalJSON() ([]byte, error) {
	str := proto.EnumName(IpSupport_CamelName, int32(e))
	return []byte("\"" + str + "\""), nil
}

var IpAccessStrings = []string{
	"IP_ACCESS_UNKNOWN",
	"IP_ACCESS_DEDICATED",
	"IP_ACCESS_DEDICATED_OR_SHARED",
	"IP_ACCESS_SHARED",
}

const (
	IpAccessIP_ACCESS_UNKNOWN             uint64 = 1 << 0
	IpAccessIP_ACCESS_DEDICATED           uint64 = 1 << 1
	IpAccessIP_ACCESS_DEDICATED_OR_SHARED uint64 = 1 << 2
	IpAccessIP_ACCESS_SHARED              uint64 = 1 << 3
)

var IpAccess_CamelName = map[int32]string{
	// IP_ACCESS_UNKNOWN -> IpAccessUnknown
	0: "IpAccessUnknown",
	// IP_ACCESS_DEDICATED -> IpAccessDedicated
	1: "IpAccessDedicated",
	// IP_ACCESS_DEDICATED_OR_SHARED -> IpAccessDedicatedOrShared
	2: "IpAccessDedicatedOrShared",
	// IP_ACCESS_SHARED -> IpAccessShared
	3: "IpAccessShared",
}
var IpAccess_CamelValue = map[string]int32{
	"IpAccessUnknown":           0,
	"IpAccessDedicated":         1,
	"IpAccessDedicatedOrShared": 2,
	"IpAccessShared":            3,
}

func (e *IpAccess) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, ok := IpAccess_CamelValue[util.CamelCase(str)]
	if !ok {
		// may be enum value instead of string
		ival, err := strconv.Atoi(str)
		val = int32(ival)
		if err == nil {
			_, ok = IpAccess_CamelName[val]
		}
	}
	if !ok {
		return errors.New(fmt.Sprintf("No enum value for %s", str))
	}
	*e = IpAccess(val)
	return nil
}

func (e IpAccess) MarshalYAML() (interface{}, error) {
	return proto.EnumName(IpAccess_CamelName, int32(e)), nil
}

// custom JSON encoding/decoding
func (e *IpAccess) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		val, ok := IpAccess_CamelValue[util.CamelCase(str)]
		if !ok {
			// may be int value instead of enum name
			ival, err := strconv.Atoi(str)
			val = int32(ival)
			if err == nil {
				_, ok = IpAccess_CamelName[val]
			}
		}
		if !ok {
			return errors.New(fmt.Sprintf("No enum value for %s", str))
		}
		*e = IpAccess(val)
		return nil
	}
	var val int32
	err = json.Unmarshal(b, &val)
	if err == nil {
		*e = IpAccess(val)
		return nil
	}
	return fmt.Errorf("No enum value for %v", b)
}

func (e IpAccess) MarshalJSON() ([]byte, error) {
	str := proto.EnumName(IpAccess_CamelName, int32(e))
	return []byte("\"" + str + "\""), nil
}

var TrackedStateStrings = []string{
	"TRACKED_STATE_UNKNOWN",
	"NOT_PRESENT",
	"CREATE_REQUESTED",
	"CREATING",
	"CREATE_ERROR",
	"READY",
	"UPDATE_REQUESTED",
	"UPDATING",
	"UPDATE_ERROR",
	"DELETE_REQUESTED",
	"DELETING",
	"DELETE_ERROR",
	"DELETE_PREPARE",
}

const (
	TrackedStateTRACKED_STATE_UNKNOWN uint64 = 1 << 0
	TrackedStateNOT_PRESENT           uint64 = 1 << 1
	TrackedStateCREATE_REQUESTED      uint64 = 1 << 2
	TrackedStateCREATING              uint64 = 1 << 3
	TrackedStateCREATE_ERROR          uint64 = 1 << 4
	TrackedStateREADY                 uint64 = 1 << 5
	TrackedStateUPDATE_REQUESTED      uint64 = 1 << 6
	TrackedStateUPDATING              uint64 = 1 << 7
	TrackedStateUPDATE_ERROR          uint64 = 1 << 8
	TrackedStateDELETE_REQUESTED      uint64 = 1 << 9
	TrackedStateDELETING              uint64 = 1 << 10
	TrackedStateDELETE_ERROR          uint64 = 1 << 11
	TrackedStateDELETE_PREPARE        uint64 = 1 << 12
)

var TrackedState_CamelName = map[int32]string{
	// TRACKED_STATE_UNKNOWN -> TrackedStateUnknown
	0: "TrackedStateUnknown",
	// NOT_PRESENT -> NotPresent
	1: "NotPresent",
	// CREATE_REQUESTED -> CreateRequested
	2: "CreateRequested",
	// CREATING -> Creating
	3: "Creating",
	// CREATE_ERROR -> CreateError
	4: "CreateError",
	// READY -> Ready
	5: "Ready",
	// UPDATE_REQUESTED -> UpdateRequested
	6: "UpdateRequested",
	// UPDATING -> Updating
	7: "Updating",
	// UPDATE_ERROR -> UpdateError
	8: "UpdateError",
	// DELETE_REQUESTED -> DeleteRequested
	9: "DeleteRequested",
	// DELETING -> Deleting
	10: "Deleting",
	// DELETE_ERROR -> DeleteError
	11: "DeleteError",
	// DELETE_PREPARE -> DeletePrepare
	12: "DeletePrepare",
}
var TrackedState_CamelValue = map[string]int32{
	"TrackedStateUnknown": 0,
	"NotPresent":          1,
	"CreateRequested":     2,
	"Creating":            3,
	"CreateError":         4,
	"Ready":               5,
	"UpdateRequested":     6,
	"Updating":            7,
	"UpdateError":         8,
	"DeleteRequested":     9,
	"Deleting":            10,
	"DeleteError":         11,
	"DeletePrepare":       12,
}

func (e *TrackedState) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, ok := TrackedState_CamelValue[util.CamelCase(str)]
	if !ok {
		// may be enum value instead of string
		ival, err := strconv.Atoi(str)
		val = int32(ival)
		if err == nil {
			_, ok = TrackedState_CamelName[val]
		}
	}
	if !ok {
		return errors.New(fmt.Sprintf("No enum value for %s", str))
	}
	*e = TrackedState(val)
	return nil
}

func (e TrackedState) MarshalYAML() (interface{}, error) {
	return proto.EnumName(TrackedState_CamelName, int32(e)), nil
}

// custom JSON encoding/decoding
func (e *TrackedState) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		val, ok := TrackedState_CamelValue[util.CamelCase(str)]
		if !ok {
			// may be int value instead of enum name
			ival, err := strconv.Atoi(str)
			val = int32(ival)
			if err == nil {
				_, ok = TrackedState_CamelName[val]
			}
		}
		if !ok {
			return errors.New(fmt.Sprintf("No enum value for %s", str))
		}
		*e = TrackedState(val)
		return nil
	}
	var val int32
	err = json.Unmarshal(b, &val)
	if err == nil {
		*e = TrackedState(val)
		return nil
	}
	return fmt.Errorf("No enum value for %v", b)
}

func (e TrackedState) MarshalJSON() ([]byte, error) {
	str := proto.EnumName(TrackedState_CamelName, int32(e))
	return []byte("\"" + str + "\""), nil
}

var CRMOverrideStrings = []string{
	"NO_OVERRIDE",
	"IGNORE_CRM_ERRORS",
	"IGNORE_CRM",
	"IGNORE_TRANSIENT_STATE",
	"IGNORE_CRM_AND_TRANSIENT_STATE",
}

const (
	CRMOverrideNO_OVERRIDE                    uint64 = 1 << 0
	CRMOverrideIGNORE_CRM_ERRORS              uint64 = 1 << 1
	CRMOverrideIGNORE_CRM                     uint64 = 1 << 2
	CRMOverrideIGNORE_TRANSIENT_STATE         uint64 = 1 << 3
	CRMOverrideIGNORE_CRM_AND_TRANSIENT_STATE uint64 = 1 << 4
)

var CRMOverride_CamelName = map[int32]string{
	// NO_OVERRIDE -> NoOverride
	0: "NoOverride",
	// IGNORE_CRM_ERRORS -> IgnoreCrmErrors
	1: "IgnoreCrmErrors",
	// IGNORE_CRM -> IgnoreCrm
	2: "IgnoreCrm",
	// IGNORE_TRANSIENT_STATE -> IgnoreTransientState
	3: "IgnoreTransientState",
	// IGNORE_CRM_AND_TRANSIENT_STATE -> IgnoreCrmAndTransientState
	4: "IgnoreCrmAndTransientState",
}
var CRMOverride_CamelValue = map[string]int32{
	"NoOverride":                 0,
	"IgnoreCrmErrors":            1,
	"IgnoreCrm":                  2,
	"IgnoreTransientState":       3,
	"IgnoreCrmAndTransientState": 4,
}

func (e *CRMOverride) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, ok := CRMOverride_CamelValue[util.CamelCase(str)]
	if !ok {
		// may be enum value instead of string
		ival, err := strconv.Atoi(str)
		val = int32(ival)
		if err == nil {
			_, ok = CRMOverride_CamelName[val]
		}
	}
	if !ok {
		return errors.New(fmt.Sprintf("No enum value for %s", str))
	}
	*e = CRMOverride(val)
	return nil
}

func (e CRMOverride) MarshalYAML() (interface{}, error) {
	return proto.EnumName(CRMOverride_CamelName, int32(e)), nil
}

// custom JSON encoding/decoding
func (e *CRMOverride) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		val, ok := CRMOverride_CamelValue[util.CamelCase(str)]
		if !ok {
			// may be int value instead of enum name
			ival, err := strconv.Atoi(str)
			val = int32(ival)
			if err == nil {
				_, ok = CRMOverride_CamelName[val]
			}
		}
		if !ok {
			return errors.New(fmt.Sprintf("No enum value for %s", str))
		}
		*e = CRMOverride(val)
		return nil
	}
	var val int32
	err = json.Unmarshal(b, &val)
	if err == nil {
		*e = CRMOverride(val)
		return nil
	}
	return fmt.Errorf("No enum value for %v", b)
}

func (e CRMOverride) MarshalJSON() ([]byte, error) {
	str := proto.EnumName(CRMOverride_CamelName, int32(e))
	return []byte("\"" + str + "\""), nil
}

func init() { proto.RegisterFile("common.proto", fileDescriptorCommon) }

var fileDescriptorCommon = []byte{
	// 452 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x92, 0xd1, 0x6e, 0xd3, 0x30,
	0x14, 0x86, 0x97, 0x76, 0x1b, 0xed, 0x69, 0xb5, 0x19, 0x8f, 0x0d, 0x31, 0x41, 0x25, 0xb8, 0xec,
	0x05, 0xbb, 0xe0, 0x09, 0x4c, 0x7c, 0x34, 0xac, 0xb6, 0x4e, 0x38, 0x76, 0x87, 0x76, 0x15, 0x85,
	0x36, 0xaa, 0x2a, 0x58, 0x12, 0xa5, 0x61, 0x6f, 0xc0, 0xbb, 0xed, 0x92, 0x47, 0x80, 0xbe, 0x06,
	0x37, 0xc8, 0x49, 0xb4, 0x36, 0x62, 0x77, 0xc9, 0x9f, 0xef, 0xff, 0x7c, 0x1c, 0x1b, 0x86, 0x8b,
	0xec, 0xee, 0x2e, 0x4b, 0xdf, 0xe7, 0x45, 0x56, 0x66, 0xbc, 0x9f, 0x2c, 0x57, 0x49, 0xf5, 0x78,
	0xf9, 0x7a, 0x95, 0x65, 0xab, 0xef, 0xc9, 0x55, 0x9c, 0xaf, 0xaf, 0xe2, 0x34, 0xcd, 0xca, 0xb8,
	0x5c, 0x67, 0xe9, 0xa6, 0x06, 0xc7, 0x13, 0xe8, 0x4d, 0xd7, 0xf7, 0x49, 0x9a, 0x6c, 0x36, 0xfc,
	0x05, 0xb0, 0xa9, 0xba, 0x41, 0x8d, 0xc6, 0x44, 0x73, 0x3d, 0xd1, 0xc1, 0x17, 0xcd, 0x0e, 0xf8,
	0x19, 0x9c, 0x3e, 0xa6, 0xc6, 0x0a, 0xab, 0x7c, 0xe6, 0xb5, 0x50, 0x79, 0xab, 0xc5, 0x4c, 0xf9,
	0xac, 0x33, 0x26, 0xe8, 0xab, 0xdc, 0xfc, 0xc8, 0xf3, 0xac, 0x28, 0xf9, 0x05, 0x70, 0x15, 0x46,
	0x66, 0x1e, 0x86, 0x01, 0xd9, 0x3d, 0xdf, 0x39, 0x3c, 0xdf, 0xcb, 0x1f, 0x8d, 0x6d, 0x7c, 0xe7,
	0xdc, 0x40, 0x4f, 0xe5, 0x62, 0xb1, 0x70, 0x03, 0xd6, 0x55, 0xe1, 0xfb, 0xed, 0x09, 0x5f, 0xc2,
	0xd9, 0x2e, 0x96, 0x28, 0x95, 0x2f, 0x2c, 0x4a, 0xe6, 0xf1, 0xb7, 0xf0, 0xe6, 0x89, 0x0f, 0x51,
	0x40, 0x91, 0xf9, 0x24, 0x08, 0x25, 0xeb, 0xb8, 0x8d, 0xec, 0x90, 0x26, 0xed, 0x8e, 0xff, 0x7a,
	0x30, 0xb4, 0x45, 0xbc, 0xf8, 0x96, 0x2c, 0x4d, 0x19, 0x97, 0x09, 0x7f, 0x05, 0xe7, 0x96, 0x84,
	0x3f, 0x41, 0x59, 0x4d, 0x8c, 0x7b, 0xab, 0x9f, 0xc2, 0x40, 0x07, 0x36, 0x0a, 0x09, 0x0d, 0x6a,
	0x5b, 0xff, 0x1b, 0x9f, 0xd0, 0x41, 0x84, 0x9f, 0xe7, 0x68, 0x6c, 0xb5, 0xd0, 0x10, 0x7a, 0x55,
	0xaa, 0xf4, 0x35, 0xeb, 0x72, 0x06, 0xc3, 0x86, 0x41, 0xa2, 0x80, 0xd8, 0x21, 0xef, 0xc3, 0x11,
	0xa1, 0x90, 0xb7, 0xec, 0xc8, 0x09, 0xe6, 0xa1, 0x6c, 0x0b, 0x8e, 0x9d, 0xa0, 0x4a, 0x9d, 0xe0,
	0x99, 0x13, 0x34, 0x4c, 0x2d, 0xe8, 0xb9, 0x96, 0xc4, 0x29, 0xb6, 0x5a, 0x7d, 0xd7, 0xaa, 0x52,
	0xd7, 0x02, 0xd7, 0x6a, 0x98, 0xba, 0x35, 0xe0, 0x1c, 0x4e, 0x9a, 0x24, 0x24, 0x0c, 0x05, 0x21,
	0x1b, 0x8e, 0x7f, 0x7a, 0x30, 0xf0, 0x69, 0x16, 0xdc, 0x27, 0x45, 0xb1, 0x5e, 0x26, 0xf5, 0x0e,
	0xa3, 0xe0, 0x06, 0x89, 0x94, 0xc4, 0xe6, 0x08, 0xaf, 0x75, 0x40, 0x18, 0xf9, 0x34, 0xab, 0x55,
	0x86, 0x79, 0xfc, 0x04, 0x60, 0x17, 0xb3, 0x0e, 0xbf, 0x84, 0x8b, 0xe6, 0xdd, 0x92, 0xd0, 0x46,
	0xa1, 0xae, 0xcf, 0x1b, 0x59, 0x97, 0xbf, 0x83, 0xd1, 0x9e, 0x42, 0x68, 0xf9, 0x1f, 0x73, 0xf8,
	0x91, 0x3d, 0xfc, 0x19, 0x1d, 0x3c, 0x6c, 0x47, 0xde, 0xaf, 0xed, 0xc8, 0xfb, 0xbd, 0x1d, 0x79,
	0x5f, 0x8f, 0xab, 0x4b, 0xfb, 0xe1, 0x5f, 0x00, 0x00, 0x00, 0xff, 0xff, 0xb9, 0x93, 0x00, 0x7e,
	0xed, 0x02, 0x00, 0x00,
}
