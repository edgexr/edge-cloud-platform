package awsec2

import (
	"time"
)

const VpcDoesNotExistError string = "vpc does not exist"
const SubnetDoesNotExistError string = "subnet does not exist"
const SubnetAlreadyExistsError string = "subnet aleady exists"
const GatewayDoesNotExistError string = "gateway does not exist"
const ResourceAlreadyAssociatedError string = "Resource.AlreadyAssociated"
const SecGrpAlreadyExistsError string = "InvalidGroup.Duplicate"
const SecGrpDoesNotExistError string = "InvalidGroup.NotFound"
const RuleAlreadyExistsError string = "InvalidPermission.Duplicate"
const RuleDoesNotExistError string = "InvalidPermission.NotFound"
const RouteTableDoesNotExistError string = "route table does not exist"
const ElasticIpDoesNotExistError string = "elastic ip does not exist"
const ImageDoesNotExistError string = "image does not exist"
const ImageNotAvailableError string = "image is not available"

const VMGroupNameTag string = "VMGroupName"
const NameTag string = "Name"

type RouteTableSearchType string

const SearchForMainRouteTable RouteTableSearchType = "main"
const SearchForRouteTableByName RouteTableSearchType = "name"

const maxVMTerminateWait = time.Minute * 2
const maxVMRunningWait = time.Minute * 3
const maxGwWait = time.Minute * 5

const MainRouteTable string = "mainRouteTable"
const MatchAnyVmName string = "anyvm"
const MatchAnyGroupName string = "anygroup"

const ArnAccountIdIdx = 4

type AwsIamUser struct {
	UserId string
	Arn    string
}

type AwsIamUserResult struct {
	User AwsIamUser
}

type AwsEc2Tag struct {
	Key   string
	Value string
}

type AwsEc2SecGrp struct {
	GroupName string
	GroupId   string
	VpcId     string
	Tags      []AwsEc2Tag
}

type AwsEc2SecGrpList struct {
	SecurityGroups []AwsEc2SecGrp
}

type AwsEc2RouteTableAssociation struct {
	Main                    bool
	RouteTableAssociationId string
}

type AwsEc2RouteTable struct {
	RouteTableId string
	VpcId        string
	Associations []AwsEc2RouteTableAssociation
	Tags         []AwsEc2Tag
}

type AwsEc2RouteTableList struct {
	RouteTables []AwsEc2RouteTable
}

type AwsEc2RouteTableCreateResult struct {
	RouteTable AwsEc2RouteTable
}

type AwsEc2Gateway struct {
	InternetGatewayId string
	Tags              []AwsEc2Tag
}

type AwsEc2GatewayList struct {
	InternetGateways []AwsEc2Gateway
}

type AwsEc2NatGateway struct {
	NatGatewayId string
	State        string
	VpcId        string
	SubnetId     string
	Tags         []AwsEc2Tag
}

type AwsEc2NatGatewayList struct {
	NatGateways []AwsEc2NatGateway
}

type AwsEc2NatGatewayCreateResult struct {
	NatGateway AwsEc2NatGateway
}

type AwsEc2Address struct {
	PublicIp           string
	AllocationId       string
	Domain             string
	NetworkBorderGroup string
	PublicIpv4Pool     string
}

type AwsEc2AddressList struct {
	Addresses []AwsEc2Address
}

type AwsEc2Subnet struct {
	CidrBlock string
	State     string
	SubnetId  string
	VpcId     string
	Name      string
	Tags      []AwsEc2Tag
}

type AwsEc2SubnetList struct {
	Subnets []AwsEc2Subnet
}

type AwsEc2Vpc struct {
	CidrBlock string
	VpcId     string
	Tags      []AwsEc2Tag
}

type AwsEc2VpcCreateResult struct {
	Vpc AwsEc2Vpc
}

type AwsEc2SubnetCreateResult struct {
	Subnet AwsEc2Subnet
}

type AwsEc2VpcList struct {
	Vpcs []AwsEc2Vpc
}

type AwsEc2NetworkInterfaceCreateSpec struct {
	AssociatePublicIpAddress bool     `json:"AssociatePublicIpAddress,omitempty"`
	SubnetId                 string   `json:"SubnetId,omitempty"`
	PrivateIpAddress         string   `json:"PrivateIpAddress,omitempty"`
	Groups                   []string `json:"Groups,omitempty"`
	DeviceIndex              int      `json:"DeviceIndex"`
}

type AwsEc2IpAddrPublicIpAssociation struct {
	AllocationId string
	PublicIp     string
}

type AwsEc2IpAddress struct {
	PrivateIpAddress string
	Association      AwsEc2IpAddrPublicIpAssociation
}

type AwsEc2NetworkInterface struct {
	VpcId              string
	SubnetId           string
	MacAddress         string
	NetworkInterfaceId string
	PrivateIpAddresses []AwsEc2IpAddress
	Association        AwsEc2IpAddrPublicIpAssociation
}

type AwsEc2NetworkInterfaceList struct {
	NetworkInterfaces []AwsEc2NetworkInterface
}

type AwsEc2NetworkInterfaceCreateResult struct {
	NetworkInterface AwsEc2NetworkInterface
}

type AwsEc2Ebs struct {
	DeleteOnTermination bool
	Status              string `json:"Status,omitempty"`
}

type AwsEc2BlockDeviceMapping struct {
	DeviceName string
	Ebs        AwsEc2Ebs
}

type AwsEc2Image struct {
	ImageId string
	OwnerId string
	State   string
	Name    string
}

type AwsEc2ImageList struct {
	Images []AwsEc2Image
}

type AwsEc2State struct {
	Code int
	Name string
}

type AwsEc2Instance struct {
	ImageId           string
	InstanceId        string
	NetworkInterfaces []AwsEc2NetworkInterface
	Tags              []AwsEc2Tag
	State             AwsEc2State
}

type AwsEc2Reservation struct {
	Instances []AwsEc2Instance
}

type AwsEc2Instances struct {
	Reservations []AwsEc2Reservation
}
