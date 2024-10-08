// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: protogen.proto

package protogen

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	descriptor "github.com/gogo/protobuf/protoc-gen-gogo/descriptor"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

var E_GenerateMatches = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51005,
	Name:          "protogen.generate_matches",
	Tag:           "varint,51005,opt,name=generate_matches",
	Filename:      "protogen.proto",
}

var E_GenerateCud = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51006,
	Name:          "protogen.generate_cud",
	Tag:           "varint,51006,opt,name=generate_cud",
	Filename:      "protogen.proto",
}

var E_ObjKey = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51007,
	Name:          "protogen.obj_key",
	Tag:           "varint,51007,opt,name=obj_key",
	Filename:      "protogen.proto",
}

var E_GenerateCache = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51008,
	Name:          "protogen.generate_cache",
	Tag:           "varint,51008,opt,name=generate_cache",
	Filename:      "protogen.proto",
}

var E_NotifyCache = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51010,
	Name:          "protogen.notify_cache",
	Tag:           "varint,51010,opt,name=notify_cache",
	Filename:      "protogen.proto",
}

var E_GenerateCudTest = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51011,
	Name:          "protogen.generate_cud_test",
	Tag:           "varint,51011,opt,name=generate_cud_test",
	Filename:      "protogen.proto",
}

var E_GenerateShowTest = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51012,
	Name:          "protogen.generate_show_test",
	Tag:           "varint,51012,opt,name=generate_show_test",
	Filename:      "protogen.proto",
}

var E_GenerateCudStreamout = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51014,
	Name:          "protogen.generate_cud_streamout",
	Tag:           "varint,51014,opt,name=generate_cud_streamout",
	Filename:      "protogen.proto",
}

var E_GenerateWaitForState = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51015,
	Name:          "protogen.generate_wait_for_state",
	Tag:           "bytes,51015,opt,name=generate_wait_for_state",
	Filename:      "protogen.proto",
}

var E_NotifyMessage = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51016,
	Name:          "protogen.notify_message",
	Tag:           "varint,51016,opt,name=notify_message",
	Filename:      "protogen.proto",
}

var E_NotifyCustomUpdate = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51017,
	Name:          "protogen.notify_custom_update",
	Tag:           "varint,51017,opt,name=notify_custom_update",
	Filename:      "protogen.proto",
}

var E_NotifyRecvHook = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51018,
	Name:          "protogen.notify_recv_hook",
	Tag:           "varint,51018,opt,name=notify_recv_hook",
	Filename:      "protogen.proto",
}

var E_NotifyFilterCloudletKey = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51019,
	Name:          "protogen.notify_filter_cloudlet_key",
	Tag:           "varint,51019,opt,name=notify_filter_cloudlet_key",
	Filename:      "protogen.proto",
}

var E_NotifyFlush = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51020,
	Name:          "protogen.notify_flush",
	Tag:           "varint,51020,opt,name=notify_flush",
	Filename:      "protogen.proto",
}

var E_NotifyPrintSendRecv = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51022,
	Name:          "protogen.notify_print_send_recv",
	Tag:           "varint,51022,opt,name=notify_print_send_recv",
	Filename:      "protogen.proto",
}

var E_Noconfig = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51026,
	Name:          "protogen.noconfig",
	Tag:           "bytes,51026,opt,name=noconfig",
	Filename:      "protogen.proto",
}

var E_Alias = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51027,
	Name:          "protogen.alias",
	Tag:           "bytes,51027,opt,name=alias",
	Filename:      "protogen.proto",
}

var E_NotRequired = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51028,
	Name:          "protogen.not_required",
	Tag:           "bytes,51028,opt,name=not_required",
	Filename:      "protogen.proto",
}

var E_GenerateCudTestUpdate = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51030,
	Name:          "protogen.generate_cud_test_update",
	Tag:           "varint,51030,opt,name=generate_cud_test_update",
	Filename:      "protogen.proto",
}

var E_GenerateAddrmTest = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51031,
	Name:          "protogen.generate_addrm_test",
	Tag:           "varint,51031,opt,name=generate_addrm_test",
	Filename:      "protogen.proto",
}

var E_ObjAndKey = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51032,
	Name:          "protogen.obj_and_key",
	Tag:           "varint,51032,opt,name=obj_and_key",
	Filename:      "protogen.proto",
}

var E_AlsoRequired = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51033,
	Name:          "protogen.also_required",
	Tag:           "bytes,51033,opt,name=also_required",
	Filename:      "protogen.proto",
}

var E_Mc2TargetZone = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51035,
	Name:          "protogen.mc2_target_zone",
	Tag:           "bytes,51035,opt,name=mc2_target_zone",
	Filename:      "protogen.proto",
}

var E_CustomKeyType = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51038,
	Name:          "protogen.custom_key_type",
	Tag:           "bytes,51038,opt,name=custom_key_type",
	Filename:      "protogen.proto",
}

var E_SingularData = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51039,
	Name:          "protogen.singular_data",
	Tag:           "varint,51039,opt,name=singular_data",
	Filename:      "protogen.proto",
}

var E_E2Edata = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51043,
	Name:          "protogen.e2edata",
	Tag:           "varint,51043,opt,name=e2edata",
	Filename:      "protogen.proto",
}

var E_GenerateCopyInFields = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51044,
	Name:          "protogen.generate_copy_in_fields",
	Tag:           "varint,51044,opt,name=generate_copy_in_fields",
	Filename:      "protogen.proto",
}

var E_UsesOrg = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51046,
	Name:          "protogen.uses_org",
	Tag:           "bytes,51046,opt,name=uses_org",
	Filename:      "protogen.proto",
}

var E_GenerateLookupBySublist = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51048,
	Name:          "protogen.generate_lookup_by_sublist",
	Tag:           "bytes,51048,opt,name=generate_lookup_by_sublist",
	Filename:      "protogen.proto",
}

var E_GenerateLookupBySubfield = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51049,
	Name:          "protogen.generate_lookup_by_subfield",
	Tag:           "bytes,51049,opt,name=generate_lookup_by_subfield",
	Filename:      "protogen.proto",
}

var E_IgnoreRefersTo = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51054,
	Name:          "protogen.ignore_refers_to",
	Tag:           "varint,51054,opt,name=ignore_refers_to",
	Filename:      "protogen.proto",
}

var E_TracksRefersTo = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51055,
	Name:          "protogen.tracks_refers_to",
	Tag:           "varint,51055,opt,name=tracks_refers_to",
	Filename:      "protogen.proto",
}

var E_ControllerApiStruct = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51056,
	Name:          "protogen.controller_api_struct",
	Tag:           "bytes,51056,opt,name=controller_api_struct",
	Filename:      "protogen.proto",
}

var E_CopyInAllFields = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51058,
	Name:          "protogen.copy_in_all_fields",
	Tag:           "varint,51058,opt,name=copy_in_all_fields",
	Filename:      "protogen.proto",
}

var E_GenerateStreamKey = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51060,
	Name:          "protogen.generate_stream_key",
	Tag:           "varint,51060,opt,name=generate_stream_key",
	Filename:      "protogen.proto",
}

var E_ParentObjName = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51062,
	Name:          "protogen.parent_obj_name",
	Tag:           "bytes,51062,opt,name=parent_obj_name",
	Filename:      "protogen.proto",
}

var E_StringKeyField = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51064,
	Name:          "protogen.string_key_field",
	Tag:           "bytes,51064,opt,name=string_key_field",
	Filename:      "protogen.proto",
}

var E_CreateOverwritesDups = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MessageOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51066,
	Name:          "protogen.create_overwrites_dups",
	Tag:           "varint,51066,opt,name=create_overwrites_dups",
	Filename:      "protogen.proto",
}

var E_VersionHash = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.EnumOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51023,
	Name:          "protogen.version_hash",
	Tag:           "varint,51023,opt,name=version_hash",
	Filename:      "protogen.proto",
}

var E_VersionHashSalt = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.EnumOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51024,
	Name:          "protogen.version_hash_salt",
	Tag:           "bytes,51024,opt,name=version_hash_salt",
	Filename:      "protogen.proto",
}

var E_CommonPrefix = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.EnumOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51051,
	Name:          "protogen.common_prefix",
	Tag:           "bytes,51051,opt,name=common_prefix",
	Filename:      "protogen.proto",
}

var E_UpgradeFunc = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.EnumValueOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51025,
	Name:          "protogen.upgrade_func",
	Tag:           "bytes,51025,opt,name=upgrade_func",
	Filename:      "protogen.proto",
}

var E_TestUpdate = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51009,
	Name:          "protogen.test_update",
	Tag:           "varint,51009,opt,name=test_update",
	Filename:      "protogen.proto",
}

var E_Backend = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51013,
	Name:          "protogen.backend",
	Tag:           "varint,51013,opt,name=backend",
	Filename:      "protogen.proto",
}

var E_Hidetag = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         52002,
	Name:          "protogen.hidetag",
	Tag:           "bytes,52002,opt,name=hidetag",
	Filename:      "protogen.proto",
}

var E_Keytag = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51047,
	Name:          "protogen.keytag",
	Tag:           "bytes,51047,opt,name=keytag",
	Filename:      "protogen.proto",
}

var E_SkipKeytagConflictCheck = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51050,
	Name:          "protogen.skip_keytag_conflict_check",
	Tag:           "varint,51050,opt,name=skip_keytag_conflict_check",
	Filename:      "protogen.proto",
}

var E_RefersTo = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51053,
	Name:          "protogen.refers_to",
	Tag:           "bytes,51053,opt,name=refers_to",
	Filename:      "protogen.proto",
}

var E_TracksRefsBy = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51057,
	Name:          "protogen.tracks_refs_by",
	Tag:           "bytes,51057,opt,name=tracks_refs_by",
	Filename:      "protogen.proto",
}

var E_RedisOnly = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51059,
	Name:          "protogen.redis_only",
	Tag:           "varint,51059,opt,name=redis_only",
	Filename:      "protogen.proto",
}

var E_Mc2Api = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51021,
	Name:          "protogen.mc2_api",
	Tag:           "bytes,51021,opt,name=mc2_api",
	Filename:      "protogen.proto",
}

var E_StreamOutIncremental = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51029,
	Name:          "protogen.stream_out_incremental",
	Tag:           "varint,51029,opt,name=stream_out_incremental",
	Filename:      "protogen.proto",
}

var E_InputRequired = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51033,
	Name:          "protogen.input_required",
	Tag:           "varint,51033,opt,name=input_required",
	Filename:      "protogen.proto",
}

var E_Mc2CustomAuthz = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51034,
	Name:          "protogen.mc2_custom_authz",
	Tag:           "varint,51034,opt,name=mc2_custom_authz",
	Filename:      "protogen.proto",
}

var E_MethodNoconfig = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51035,
	Name:          "protogen.method_noconfig",
	Tag:           "bytes,51035,opt,name=method_noconfig",
	Filename:      "protogen.proto",
}

var E_MethodAlsoRequired = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51036,
	Name:          "protogen.method_also_required",
	Tag:           "bytes,51036,opt,name=method_also_required",
	Filename:      "protogen.proto",
}

var E_MethodNotRequired = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51037,
	Name:          "protogen.method_not_required",
	Tag:           "bytes,51037,opt,name=method_not_required",
	Filename:      "protogen.proto",
}

var E_NonStandardShow = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51040,
	Name:          "protogen.non_standard_show",
	Tag:           "varint,51040,opt,name=non_standard_show",
	Filename:      "protogen.proto",
}

var E_Mc2ApiNotifyroot = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51042,
	Name:          "protogen.mc2_api_notifyroot",
	Tag:           "varint,51042,opt,name=mc2_api_notifyroot",
	Filename:      "protogen.proto",
}

var E_Mc2ApiRequiresOrg = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51045,
	Name:          "protogen.mc2_api_requires_org",
	Tag:           "bytes,51045,opt,name=mc2_api_requires_org",
	Filename:      "protogen.proto",
}

var E_CliCmd = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         51050,
	Name:          "protogen.cli_cmd",
	Tag:           "bytes,51050,opt,name=cli_cmd",
	Filename:      "protogen.proto",
}

var E_Mc2CustomValidateInput = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.MethodOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51061,
	Name:          "protogen.mc2_custom_validate_input",
	Tag:           "varint,51061,opt,name=mc2_custom_validate_input",
	Filename:      "protogen.proto",
}

var E_DummyServer = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.ServiceOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51026,
	Name:          "protogen.dummy_server",
	Tag:           "varint,51026,opt,name=dummy_server",
	Filename:      "protogen.proto",
}

var E_InternalApi = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.ServiceOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51065,
	Name:          "protogen.internal_api",
	Tag:           "varint,51065,opt,name=internal_api",
	Filename:      "protogen.proto",
}

var E_RedisApi = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.ServiceOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         51066,
	Name:          "protogen.redis_api",
	Tag:           "varint,51066,opt,name=redis_api",
	Filename:      "protogen.proto",
}

func init() {
	proto.RegisterExtension(E_GenerateMatches)
	proto.RegisterExtension(E_GenerateCud)
	proto.RegisterExtension(E_ObjKey)
	proto.RegisterExtension(E_GenerateCache)
	proto.RegisterExtension(E_NotifyCache)
	proto.RegisterExtension(E_GenerateCudTest)
	proto.RegisterExtension(E_GenerateShowTest)
	proto.RegisterExtension(E_GenerateCudStreamout)
	proto.RegisterExtension(E_GenerateWaitForState)
	proto.RegisterExtension(E_NotifyMessage)
	proto.RegisterExtension(E_NotifyCustomUpdate)
	proto.RegisterExtension(E_NotifyRecvHook)
	proto.RegisterExtension(E_NotifyFilterCloudletKey)
	proto.RegisterExtension(E_NotifyFlush)
	proto.RegisterExtension(E_NotifyPrintSendRecv)
	proto.RegisterExtension(E_Noconfig)
	proto.RegisterExtension(E_Alias)
	proto.RegisterExtension(E_NotRequired)
	proto.RegisterExtension(E_GenerateCudTestUpdate)
	proto.RegisterExtension(E_GenerateAddrmTest)
	proto.RegisterExtension(E_ObjAndKey)
	proto.RegisterExtension(E_AlsoRequired)
	proto.RegisterExtension(E_Mc2TargetZone)
	proto.RegisterExtension(E_CustomKeyType)
	proto.RegisterExtension(E_SingularData)
	proto.RegisterExtension(E_E2Edata)
	proto.RegisterExtension(E_GenerateCopyInFields)
	proto.RegisterExtension(E_UsesOrg)
	proto.RegisterExtension(E_GenerateLookupBySublist)
	proto.RegisterExtension(E_GenerateLookupBySubfield)
	proto.RegisterExtension(E_IgnoreRefersTo)
	proto.RegisterExtension(E_TracksRefersTo)
	proto.RegisterExtension(E_ControllerApiStruct)
	proto.RegisterExtension(E_CopyInAllFields)
	proto.RegisterExtension(E_GenerateStreamKey)
	proto.RegisterExtension(E_ParentObjName)
	proto.RegisterExtension(E_StringKeyField)
	proto.RegisterExtension(E_CreateOverwritesDups)
	proto.RegisterExtension(E_VersionHash)
	proto.RegisterExtension(E_VersionHashSalt)
	proto.RegisterExtension(E_CommonPrefix)
	proto.RegisterExtension(E_UpgradeFunc)
	proto.RegisterExtension(E_TestUpdate)
	proto.RegisterExtension(E_Backend)
	proto.RegisterExtension(E_Hidetag)
	proto.RegisterExtension(E_Keytag)
	proto.RegisterExtension(E_SkipKeytagConflictCheck)
	proto.RegisterExtension(E_RefersTo)
	proto.RegisterExtension(E_TracksRefsBy)
	proto.RegisterExtension(E_RedisOnly)
	proto.RegisterExtension(E_Mc2Api)
	proto.RegisterExtension(E_StreamOutIncremental)
	proto.RegisterExtension(E_InputRequired)
	proto.RegisterExtension(E_Mc2CustomAuthz)
	proto.RegisterExtension(E_MethodNoconfig)
	proto.RegisterExtension(E_MethodAlsoRequired)
	proto.RegisterExtension(E_MethodNotRequired)
	proto.RegisterExtension(E_NonStandardShow)
	proto.RegisterExtension(E_Mc2ApiNotifyroot)
	proto.RegisterExtension(E_Mc2ApiRequiresOrg)
	proto.RegisterExtension(E_CliCmd)
	proto.RegisterExtension(E_Mc2CustomValidateInput)
	proto.RegisterExtension(E_DummyServer)
	proto.RegisterExtension(E_InternalApi)
	proto.RegisterExtension(E_RedisApi)
}

func init() { proto.RegisterFile("protogen.proto", fileDescriptor_f3d59d67231a6957) }

var fileDescriptor_f3d59d67231a6957 = []byte{
	// 1539 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x97, 0x49, 0x73, 0x1c, 0xb7,
	0x15, 0x80, 0x8b, 0x95, 0x8a, 0x48, 0x81, 0x9b, 0x38, 0xa4, 0x96, 0x28, 0x09, 0xa3, 0xdc, 0x72,
	0xa2, 0xaa, 0x98, 0x83, 0x4a, 0x88, 0xa2, 0xca, 0x88, 0x12, 0x23, 0x8a, 0x12, 0x29, 0x71, 0x28,
	0x29, 0xa5, 0xa4, 0x82, 0x60, 0xd0, 0x98, 0x19, 0x70, 0xba, 0x81, 0x0e, 0x80, 0x26, 0xdd, 0xfa,
	0x11, 0x3e, 0xfa, 0x07, 0xf8, 0x7f, 0x78, 0xdf, 0xe4, 0x5d, 0xde, 0x2d, 0xaf, 0x2a, 0x7a, 0x97,
	0xcb, 0xfb, 0x52, 0xb6, 0x4f, 0x2e, 0xa0, 0x81, 0x9e, 0xe1, 0x52, 0x85, 0xd6, 0xcd, 0xb4, 0xfa,
	0xfb, 0x06, 0xef, 0xe1, 0xe1, 0xe1, 0x01, 0x8c, 0xa5, 0x52, 0x68, 0xd1, 0xa6, 0x7c, 0xc6, 0xfe,
	0x47, 0x6d, 0xc8, 0xff, 0x7d, 0xf8, 0x48, 0x5b, 0x88, 0x76, 0x4c, 0x8f, 0xda, 0xff, 0xd1, 0xcc,
	0x5a, 0x47, 0x23, 0xaa, 0x88, 0x64, 0xa9, 0x16, 0xb2, 0xf8, 0x16, 0x9e, 0x07, 0xfb, 0xda, 0x94,
	0x53, 0x89, 0x35, 0x45, 0x09, 0xd6, 0xa4, 0x43, 0x55, 0xed, 0x4f, 0x33, 0x05, 0x36, 0xe3, 0xb1,
	0x99, 0x0b, 0x54, 0x29, 0xdc, 0xa6, 0xcb, 0xa9, 0x66, 0x82, 0xab, 0x43, 0x0f, 0xdc, 0xfb, 0x9b,
	0x23, 0x03, 0x7f, 0x19, 0x5a, 0x19, 0xf7, 0xe8, 0x85, 0x82, 0x84, 0xa7, 0xc1, 0x48, 0x69, 0x23,
	0x59, 0x14, 0x36, 0x3d, 0xe8, 0x4c, 0xc3, 0x1e, 0x9b, 0xcb, 0x22, 0x08, 0xc1, 0xa0, 0x68, 0xae,
	0xa1, 0x2e, 0xcd, 0xc3, 0x82, 0x87, 0x9c, 0x60, 0x8f, 0x68, 0xae, 0x2d, 0xd2, 0x1c, 0x9e, 0x05,
	0x63, 0xbd, 0x15, 0x60, 0xd2, 0xa1, 0x61, 0xc5, 0xc3, 0x4e, 0x31, 0x5a, 0xae, 0xc1, 0x70, 0x26,
	0x16, 0x2e, 0x34, 0x6b, 0xe5, 0x55, 0x3d, 0x8f, 0xfa, 0x58, 0x0a, 0xac, 0xb0, 0x5c, 0x00, 0x13,
	0xfd, 0x19, 0x41, 0x9a, 0x2a, 0x1d, 0x56, 0x3d, 0xb6, 0x3d, 0xc1, 0x73, 0x59, 0xb4, 0x4a, 0x95,
	0x86, 0xcb, 0xa0, 0x56, 0xea, 0x54, 0x47, 0x6c, 0x54, 0xf4, 0x3d, 0xee, 0x7c, 0xe5, 0x5e, 0x37,
	0x3a, 0x62, 0xc3, 0x0a, 0xaf, 0x82, 0x03, 0x5b, 0xd6, 0xa7, 0xb4, 0xa4, 0x38, 0x11, 0x59, 0x05,
	0xe9, 0x93, 0x4e, 0x3a, 0xd5, 0xb7, 0xc8, 0x86, 0xc7, 0xe1, 0xbf, 0xc0, 0xc1, 0x52, 0xbc, 0x81,
	0x99, 0x46, 0x2d, 0x21, 0x91, 0xd2, 0x58, 0x57, 0xc8, 0xe4, 0x53, 0xd6, 0xbc, 0xb7, 0x67, 0xbe,
	0x8a, 0x99, 0x9e, 0x17, 0xb2, 0x61, 0x70, 0xb3, 0xc5, 0x6e, 0x63, 0x92, 0x02, 0x0b, 0x0b, 0x6f,
	0xf8, 0x2d, 0x2e, 0x40, 0xf7, 0xaf, 0xb0, 0x01, 0xa6, 0xfc, 0x16, 0x67, 0x4a, 0x8b, 0x04, 0x65,
	0x69, 0x54, 0x69, 0x81, 0x4f, 0x3b, 0x5f, 0xcd, 0x6d, 0xb5, 0xa5, 0x2f, 0x5b, 0x18, 0x2e, 0x82,
	0x7d, 0x4e, 0x2a, 0x29, 0x59, 0x47, 0x1d, 0x21, 0xba, 0x61, 0xe1, 0x33, 0x4e, 0xe8, 0x22, 0x5b,
	0xa1, 0x64, 0xfd, 0xac, 0x10, 0x5d, 0xf8, 0x5f, 0x70, 0xd8, 0xc9, 0x5a, 0x2c, 0xd6, 0x54, 0x22,
	0x12, 0x8b, 0x2c, 0x8a, 0xa9, 0xae, 0x76, 0x3a, 0x9e, 0x75, 0xda, 0x83, 0x85, 0x64, 0xde, 0x3a,
	0xe6, 0x9c, 0xc2, 0x1c, 0x97, 0x5e, 0x91, 0xb7, 0xe2, 0x4c, 0x75, 0xc2, 0xc6, 0xe7, 0xb6, 0x16,
	0xf9, 0xbc, 0xa1, 0xe0, 0x15, 0x70, 0xc0, 0x59, 0x52, 0xc9, 0xb8, 0x46, 0x8a, 0xf2, 0xc8, 0x46,
	0x1f, 0xf6, 0xbd, 0xe0, 0x7c, 0x93, 0x85, 0xe0, 0xa2, 0xe1, 0x1b, 0x94, 0x47, 0x26, 0x03, 0xf0,
	0xef, 0x60, 0x88, 0x0b, 0x22, 0x78, 0x8b, 0xb5, 0xc3, 0xa6, 0x97, 0x5d, 0xd1, 0x94, 0x08, 0x3c,
	0x06, 0x7e, 0x8b, 0x63, 0x86, 0x2b, 0x34, 0xb4, 0x57, 0x1c, 0x5b, 0x7c, 0xef, 0xb2, 0x82, 0x24,
	0xfd, 0x7f, 0xc6, 0x24, 0xad, 0xd0, 0xc6, 0x5e, 0x75, 0xbc, 0xc9, 0xca, 0x8a, 0xa3, 0xe0, 0x35,
	0x70, 0x68, 0xc7, 0xd1, 0xaf, 0x5c, 0x61, 0xaf, 0xbb, 0xbc, 0xec, 0xdf, 0xd6, 0x01, 0x5c, 0x91,
	0x5d, 0x02, 0x93, 0xa5, 0x1b, 0x47, 0x91, 0x4c, 0x2a, 0x36, 0x82, 0x37, 0x9c, 0xb6, 0x6c, 0x4a,
	0x75, 0x03, 0xdb, 0x4e, 0x50, 0x07, 0xc3, 0xa6, 0xeb, 0x62, 0x1e, 0x55, 0xab, 0xad, 0x37, 0x9d,
	0x6a, 0xaf, 0x68, 0xae, 0xd5, 0x79, 0x64, 0xaa, 0x69, 0x1e, 0x8c, 0xe2, 0x58, 0x89, 0xbb, 0x48,
	0xdc, 0x2d, 0x97, 0xb8, 0x11, 0xc3, 0x95, 0x99, 0x5b, 0x00, 0xe3, 0x09, 0x99, 0x45, 0x1a, 0xcb,
	0x36, 0xd5, 0xe8, 0xba, 0xe0, 0x15, 0x12, 0xf6, 0xb6, 0x33, 0x8d, 0x26, 0x64, 0x76, 0xd5, 0x82,
	0xd7, 0x04, 0xa7, 0x46, 0xe5, 0xce, 0x76, 0x97, 0xe6, 0x48, 0xe7, 0x69, 0x05, 0xd5, 0x7b, 0x5e,
	0x55, 0x90, 0x8b, 0x34, 0x5f, 0xcd, 0x53, 0x6a, 0xa2, 0x53, 0x8c, 0xb7, 0xb3, 0x18, 0x4b, 0x14,
	0x61, 0x8d, 0xc3, 0xa2, 0xf7, 0x5d, 0x8a, 0x46, 0x3c, 0x77, 0x1a, 0x6b, 0x0c, 0xff, 0x06, 0x06,
	0xe9, 0x2c, 0xad, 0x66, 0xf8, 0xc0, 0x19, 0x3c, 0xb1, 0xa5, 0xad, 0x12, 0x91, 0xe6, 0x88, 0x71,
	0xd4, 0x62, 0x34, 0x8e, 0x2a, 0x54, 0xf9, 0x87, 0x3b, 0x1a, 0xb6, 0x48, 0xf3, 0x05, 0x3e, 0x6f,
	0x71, 0x78, 0x02, 0x0c, 0x65, 0x8a, 0x2a, 0x24, 0x64, 0x85, 0xc3, 0xf6, 0xb1, 0x4b, 0xd1, 0xa0,
	0x41, 0x96, 0x65, 0xdb, 0x34, 0xaa, 0x72, 0x5d, 0xb1, 0x10, 0xdd, 0x2c, 0x45, 0xcd, 0x1c, 0xa9,
	0xac, 0x19, 0xb3, 0x2a, 0x75, 0xf9, 0xa9, 0xf3, 0x95, 0xc1, 0x9d, 0xb7, 0x8e, 0x53, 0x79, 0xa3,
	0x30, 0xc0, 0xff, 0x81, 0xdf, 0xef, 0xee, 0xb7, 0xc1, 0x87, 0x7f, 0xe0, 0x33, 0xf7, 0x03, 0x87,
	0x76, 0xf9, 0x01, 0xab, 0x30, 0x7d, 0x9b, 0xb5, 0xb9, 0x90, 0x14, 0x49, 0xda, 0xa2, 0x52, 0x21,
	0x2d, 0xc2, 0xda, 0x2f, 0x7d, 0xdf, 0x2e, 0xd0, 0x15, 0x4b, 0xae, 0x0a, 0x23, 0xd3, 0x12, 0x93,
	0xae, 0xba, 0x1b, 0xd9, 0x57, 0x5e, 0x56, 0xa0, 0xa5, 0xec, 0x32, 0xd8, 0x4f, 0x04, 0xd7, 0x52,
	0xc4, 0x31, 0x95, 0x08, 0xa7, 0xcc, 0xdc, 0xd2, 0x19, 0xa9, 0x90, 0xd6, 0xaf, 0x5d, 0xd4, 0x93,
	0x3d, 0xbe, 0x9e, 0xb2, 0x86, 0xa5, 0xe1, 0x12, 0xa8, 0xf9, 0x0a, 0xc2, 0x71, 0x5c, 0xb9, 0x8a,
	0xbe, 0xf5, 0xb3, 0x09, 0xb1, 0xd5, 0x53, 0x8f, 0x63, 0x57, 0x40, 0xfd, 0x3d, 0xa9, 0x18, 0x23,
	0xaa, 0x35, 0x92, 0xef, 0xb7, 0xf7, 0xa4, 0x62, 0x88, 0x30, 0x0d, 0x65, 0x01, 0x8c, 0xa7, 0x58,
	0x52, 0xae, 0x91, 0x69, 0x4d, 0x1c, 0x27, 0x15, 0x4e, 0xef, 0x8f, 0xfe, 0xf4, 0x16, 0xe4, 0x72,
	0x73, 0x6d, 0x09, 0x27, 0xf6, 0x5a, 0x56, 0x5a, 0x32, 0xde, 0xb6, 0x8d, 0xa0, 0x62, 0xd5, 0xfc,
	0xe4, 0x5c, 0x63, 0x05, 0xba, 0x48, 0x73, 0x1b, 0xab, 0x99, 0x9a, 0x88, 0xa4, 0x26, 0x50, 0xb1,
	0x4e, 0xe5, 0x86, 0x64, 0x9a, 0x2a, 0x14, 0x65, 0x69, 0x85, 0xf4, 0xfd, 0xe2, 0x0f, 0x61, 0x21,
	0x58, 0x2e, 0xf9, 0xd3, 0x59, 0xaa, 0x60, 0x1d, 0x8c, 0xac, 0x53, 0xa9, 0x98, 0xe0, 0xa8, 0x83,
	0x55, 0xa7, 0xf6, 0x87, 0x1d, 0xba, 0x33, 0x3c, 0x4b, 0xbc, 0xeb, 0x45, 0x7f, 0x19, 0x3b, 0xe6,
	0x2c, 0x56, 0x1d, 0x78, 0x0e, 0x4c, 0xf4, 0x2b, 0x90, 0xc2, 0xb1, 0x0e, 0x78, 0x6e, 0xba, 0x30,
	0xc7, 0xfb, 0x3c, 0x0d, 0x1c, 0x6b, 0x38, 0x07, 0x46, 0x89, 0x48, 0x12, 0xc1, 0x51, 0x2a, 0x69,
	0x8b, 0xdd, 0x13, 0xf0, 0x7c, 0xee, 0xbb, 0x79, 0x01, 0x5d, 0xb4, 0x0c, 0x9c, 0x07, 0x23, 0x59,
	0xda, 0x96, 0x38, 0xa2, 0xa8, 0x95, 0x71, 0x52, 0xfb, 0xf3, 0xae, 0x8e, 0x2b, 0x38, 0xce, 0xca,
	0x24, 0xbd, 0xe4, 0xef, 0x53, 0x07, 0xce, 0x67, 0x9c, 0xc0, 0x7f, 0x80, 0xe1, 0xfe, 0x2b, 0xf4,
	0x8f, 0x3b, 0x34, 0x76, 0x6f, 0xbc, 0xe2, 0x11, 0x97, 0x1b, 0xa0, 0x7b, 0xb7, 0xe6, 0x71, 0x30,
	0xd8, 0xc4, 0xa4, 0x4b, 0x79, 0x14, 0xa2, 0x9f, 0xf0, 0x7d, 0xd7, 0x7d, 0x6f, 0xd0, 0x0e, 0x8b,
	0xa8, 0xc6, 0xed, 0x10, 0x7a, 0xff, 0x7d, 0xae, 0x35, 0xba, 0xef, 0xe1, 0x31, 0xb0, 0xa7, 0x4b,
	0xf3, 0x0a, 0xe4, 0x27, 0x2e, 0x6a, 0xf7, 0x39, 0xfc, 0x0f, 0x38, 0xac, 0xba, 0x2c, 0x45, 0xc5,
	0x9f, 0xc8, 0x4c, 0x35, 0x31, 0x23, 0x1a, 0x91, 0x0e, 0x25, 0xdd, 0x90, 0xec, 0x8e, 0x1f, 0xfd,
	0x8c, 0x62, 0xd1, 0x1a, 0xe6, 0x9c, 0x60, 0xce, 0xf0, 0xf0, 0x04, 0xd8, 0xdb, 0xeb, 0x4d, 0x01,
	0xd9, 0x17, 0x7e, 0xb6, 0x92, 0xbe, 0x27, 0x9d, 0x01, 0x63, 0xbd, 0x06, 0xa7, 0x50, 0x33, 0x0f,
	0x29, 0xbe, 0xf1, 0xb5, 0x51, 0x36, 0x37, 0x75, 0x2a, 0x87, 0x27, 0x01, 0x90, 0x34, 0x62, 0x0a,
	0x09, 0x1e, 0x07, 0x15, 0xdf, 0xf9, 0x89, 0xc3, 0x22, 0xcb, 0x3c, 0xce, 0xcd, 0xb6, 0x98, 0x49,
	0x01, 0xa7, 0xac, 0x36, 0xbd, 0xcb, 0xc9, 0xd3, 0x1d, 0x51, 0xd2, 0xcf, 0xfb, 0xec, 0x26, 0x64,
	0xb6, 0x9e, 0x32, 0x33, 0xb4, 0xba, 0x2e, 0x25, 0x32, 0x8d, 0x18, 0x27, 0x92, 0x26, 0x94, 0x6b,
	0x1c, 0x07, 0x4d, 0xaf, 0xf9, 0x23, 0x5c, 0xf0, 0xcb, 0x99, 0x5e, 0xe8, 0xd1, 0xf0, 0x9f, 0x60,
	0x8c, 0xf1, 0x34, 0xeb, 0x1b, 0x1f, 0x43, 0xbe, 0x5b, 0xfe, 0x75, 0x62, 0xb9, 0x72, 0x0a, 0x3a,
	0x07, 0xf6, 0x99, 0xd8, 0xdc, 0xf8, 0x82, 0x33, 0xdd, 0xb9, 0x1e, 0x54, 0xbd, 0xe5, 0xaf, 0x90,
	0x84, 0xcc, 0x16, 0xaf, 0x92, 0xba, 0xe1, 0xec, 0x44, 0x65, 0x3f, 0x44, 0xe5, 0x40, 0x1d, 0x52,
	0xf9, 0x81, 0x6a, 0xac, 0x00, 0x97, 0xfc, 0x54, 0xbd, 0x02, 0xa6, 0x9c, 0x6a, 0xeb, 0xac, 0x17,
	0xf2, 0xbd, 0xe3, 0x7c, 0xb5, 0x82, 0xae, 0xf7, 0x0f, 0x7c, 0x17, 0xc1, 0x64, 0xb9, 0xbc, 0xbb,
	0x48, 0xdc, 0xbb, 0x4e, 0x39, 0xe1, 0x97, 0xd8, 0x4b, 0xde, 0x79, 0x30, 0xc1, 0x05, 0x37, 0x0f,
	0x4e, 0x1e, 0x61, 0x19, 0xd9, 0xc7, 0x72, 0xd0, 0x77, 0xdb, 0x5f, 0x6d, 0x5c, 0xf0, 0x86, 0x23,
	0xcd, 0x4b, 0xd9, 0x5c, 0x95, 0xae, 0xcc, 0x50, 0xf1, 0x4e, 0x91, 0x42, 0xe8, 0xa0, 0x6e, 0xd3,
	0xbf, 0xba, 0x8b, 0x8a, 0x5b, 0x2a, 0x49, 0x78, 0x09, 0x4c, 0x79, 0x9f, 0x0b, 0xb6, 0x98, 0xbb,
	0x42, 0xc6, 0x8f, 0xca, 0x80, 0xad, 0xd1, 0x45, 0x6b, 0x07, 0xb0, 0xe3, 0x60, 0x90, 0xc4, 0x0c,
	0x91, 0x24, 0x9c, 0xb6, 0x3b, 0xfe, 0x24, 0x90, 0x98, 0xcd, 0x25, 0x11, 0xfc, 0x37, 0xf8, 0x5d,
	0x5f, 0xa1, 0xad, 0xe3, 0x98, 0x99, 0x6e, 0x89, 0x6c, 0x35, 0x06, 0x65, 0x3f, 0xb8, 0x20, 0x0f,
	0x94, 0x15, 0x77, 0xc5, 0x09, 0x16, 0x0c, 0x6f, 0xde, 0x52, 0x51, 0x96, 0x24, 0x39, 0x52, 0x54,
	0xae, 0x53, 0xb9, 0xcb, 0x05, 0xd9, 0xa0, 0x72, 0x9d, 0x91, 0x6d, 0xef, 0xb8, 0xa1, 0x95, 0x61,
	0x8b, 0x35, 0x2c, 0x65, 0x2c, 0x8c, 0x6b, 0x2a, 0x39, 0x8e, 0xed, 0x61, 0x0f, 0x5a, 0x7e, 0xf6,
	0x16, 0x8f, 0x99, 0x23, 0x7f, 0x12, 0x14, 0xad, 0xa3, 0x9a, 0xc2, 0xdf, 0xd4, 0x43, 0x96, 0xa9,
	0xa7, 0xec, 0xd4, 0xc8, 0x8d, 0xcd, 0xe9, 0x81, 0x9b, 0x9b, 0xd3, 0x03, 0xb7, 0x37, 0xa7, 0x07,
	0x9a, 0x7b, 0x2c, 0xf8, 0xd7, 0x5f, 0x03, 0x00, 0x00, 0xff, 0xff, 0x2b, 0xf0, 0x70, 0x35, 0x7f,
	0x13, 0x00, 0x00,
}
