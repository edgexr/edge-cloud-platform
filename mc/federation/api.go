package federation

// Federation API Standard Definitions
// ===================================
type OperatorRegistrationRequest struct {
	// Request ID for tracking federation request
	RequestId string `json:"requestId"`
	// Globally unique string to identify an operator platform
	// required: true
	OperatorId string `json:"operator"`
	// ISO 3166-1 Alpha-2 code for the country where operator platform is located
	// required: true
	CountryCode string `json:"country"`
	// Origin OP federation ID
	OrigFederationId string `json:"origFederationId"`
	// Destination OP federation ID
	DestFederationId string `json:"destFederationId"`
	// If partner OP shall endorse lead OP applications
	ApplicationAnchormentReq bool `json:"applicationAnchormentReq"`
}

type OperatorRegistrationResponse struct {
	// Request id as sent in federation request
	RequestId string `json:"requestId"`
	// Globally unique string to identify an operator platform
	OrigOperatorId string `json:"origOperatorId"`
	// Globally unique string to identify an operator platform
	PartnerOperatorId string `json:"partnerOperatorId"`
	// Origin OP federation ID
	OrigFederationId string `json:"origFederationId"`
	// Destination OP federation ID
	DestFederationId string `json:"destFederationId"`
	// Mobile country code of operator sending the request
	MCC string `json:"MCC"`
	// Mobile network codes of operator sending the request
	MNC []string `json:"MNC"`
	// IP and Port of discovery service URL of OP
	LocatorEndPoint string `json:"locatorEndPoint"`
	// List of zones partner OP is willing to share
	PartnerZone []ZoneInfo `json:"partnerZone"`
}

type UpdateMECNetConf struct {
	// Request id as sent in federation request
	RequestId string `json:"requestId"`
	// Globally unique string to identify an operator platform
	Operator string `json:"operator"`
	// ISO 3166-1 Alpha-2 code for the country where operator platform is located
	Country string `json:"country"`
	// Origin OP federation ID
	OrigFederationId string `json:"origFederationId"`
	// Destination OP federation ID
	DestFederationId string `json:"destFederationId"`
	// Mobile country code of operator sending the request
	MCC string `json:"MCC"`
	// Mobile network codes of operator sending the request
	MNC []string `json:"MNC"`
	// IP and Port of discovery service URL of OP
	LocatorEndPoint string `json:"locatorEndPoint"`
}

type FederationRequest struct {
	// Request id as sent in federation request
	RequestId string `json:"requestId"`
	// Globally unique string to identify an operator platform
	Operator string `json:"operator"`
	// ISO 3166-1 Alpha-2 code for the country where operator platform is located
	Country string `json:"country"`
	// Origin OP federation ID
	OrigFederationId string `json:"origFederationId"`
	// Destination OP federation ID
	DestFederationId string `json:"destFederationId"`
}

type OperatorZoneRegister struct {
	// Request id as sent in federation request
	RequestId string `json:"requestId"`
	// Globally unique string to identify an operator platform
	Operator string `json:"operator"`
	// ISO 3166-1 Alpha-2 code for the country where operator platform is located
	Country string `json:"country"`
	// Unique identifier for zone in the country of partner operator
	Zones []string `json:"zones"`
	// Origin OP federation ID
	OrigFederationId string `json:"origFederationId"`
	// Destination OP federation ID
	DestFederationId string `json:"destFederationId"`
}

type OperatorZoneRegisterResponse struct {
	// Request id as sent in federation request
	RequestId string `json:"requestId"`
	// Globally unique string to identify an operator platform
	LeadOperatorId string `json:"leadOperatorId"`
	// Globally unique string to identify an operator platform
	PartnerOperatorId string `json:"partnerOperatorId"`
	// Federation ID
	FederationId string `json:"federationId"`
	// Partner OP zone details
	Zone ZoneRegisterDetails `json:"zone"`
}

type ZoneRegisterDetails struct {
	// Globally Unique identifier of the zone
	ZoneId string `json:"zoneId"`
	// Federation key of operator responding the request
	RegistrationToken string `json:"registrationToken"`
	// Guaranteed resource details on a zone
	GuaranteedResources ZoneResourceInfo `json:"guaranteedResources"`
	// Upper limit quota of resources in a zone
	UpperLimitQuota ZoneResourceInfo `json:"upperLimitQuota"`
}

// Resource details on a zone
type ZoneResourceInfo struct {
	// Total maximum cpu physical cores that can be allocated for lead operator user apps
	CPU int64 `json:"cpu"`
	// Total maximum memory (GBs) that can be allocated for lead operator user apps
	RAM int64 `json:"ram"`
	// Total maximum disk (Gbs) that can be allocated for lead operator user apps
	Disk int64 `json:"disk"`
	// Total maximum gpu that can be allocated for lead operator user apps
	GPU int64 `json:"gpu"`
}

type ZoneInfo struct {
	// Globally Unique identifier of the zone
	ZoneId string `json:"zoneId"`
	// GPS co-ordinates associated with the zone (in decimal format)
	GeoLocation string `json:"geoLocation"`
	// Comma seperated list of cities under this zone
	City string `json:"city"`
	// Comma seperated list of states under this zone
	State string `json:"state"`
	// Type of locality eg rural, urban etc.
	Locality string `json:"locality"`
	// Number of edges in the zone
	EdgeCount int `json:"edgeCount"`
}

type ZoneRequest struct {
	// Request id as sent in federation request
	RequestId string `json:"requestId"`
	// Globally unique string to identify an operator platform
	Operator string `json:"operator"`
	// ISO 3166-1 Alpha-2 code for the country where operator platform is located
	Country string `json:"country"`
	// Zone identifier of partner operator
	Zone string `json:"zone"`
	// Origin OP federation ID
	OrigFederationId string `json:"origFederationId"`
	// Destination OP federation ID
	DestFederationId string `json:"destFederationId"`
}

type NotifyPartnerOperatorZone struct {
	// Request id as sent in federation request
	RequestId string `json:"requestId"`
	// Globally unique string to identify an operator platform
	Operator string `json:"operator"`
	// ISO 3166-1 Alpha-2 code for the country where operator platform is located
	Country string `json:"country"`
	// Origin OP federation ID
	OrigFederationId string `json:"origFederationId"`
	// Destination OP federation ID
	DestFederationId string `json:"destFederationId"`
	// Details of the new zone to be shared
	PartnerZone ZoneInfo `json:"partnerZone"`
}

type AppArtifact struct {
	// required: true
	// Request id for tracking the request over federation interface
	RequestId string `json:"requestId"`
	// required: true
	// Name of the artifact file (WinZip format)
	FileName []byte `json:"filename"`
	// pattern: "[a-z0-9A-Z]"
	// minLength: 1, maxLength: 64
	// required: true
	// Name of the artifact
	ArtifactName string `json:"artifactName"`
	// pattern: ^[a-z0-9][a-z0-9_-]*[a-z0-9]$
	// minLength: 8, maxLength: 64
	// required: true
	// Identifer of the application
	AppId string `json:"appId"`
	// required: true
	// Application User ID
	UserId string `json:"userId"`
	// required: true
	// Application version
	Version string `json:"version"`
	// pattern: ^[\w][\w_-]*[\w]$
	// minLength: 8, maxLength: 128
	// required: true
	// Federation key of OP initiating the request
	LeadFederationId string `json:"leadfederationId"`
	// pattern: ^[\w][\w_-]*[\w]$
	// minLength: 8, maxLength: 128
	// required: true
	// Federation key of partner OP
	PartnerFederationId string `json:"partnerfederationId"`
	// pattern: ^[\w][\w_-]*[\w]$
	// minLength: 8, maxLength: 32
	// required: true
	// Identifier of operator assosited with the OP initiating the request
	Operator string `json:"operator"`
	// required: true
	// pattern: ^[A-Z]{2}$
	// ISO 3166-1 Alpha-2 code for the country of OP initiating the request
	Country string `json:"country"`
	// Name of terraform file (zip format). This zip contains all terraform scripts (Kubernetes v1.13 native)
	TerraformFileId string `json:"terraformFileId"`
	// Name of helm file (zip format). This zip contains helm chart
	HelmFileId string `json:"helmFileId"`
	// Name of component. An application may have more than one component, each one associated with a separate container image
	Components []string `json:"components"`
	// enum: TOSCA, TERRAFORM, HELM, GMEC
	// Descriptor type associated with the application
	AppDescriptorType string `json:"appDescriptorType"`
	// String in app descriptor type contains the format of content in package field
	Package string `json:"package"`
	// pattern: "^[a-z0-9]([a-z0-9]*[a-z0-9])?$"
	// minLength: 1, maxLength: 16
	// System generated unique identifier for the artifact being uploaded
	ArtifactId string `json:"artifactId"`
}

type AppArtifactRequest struct {
	// required: true
	// request identifier
	RequestId string `json:"requestId"`
	// required: true
	// Identifier of the artifact
	ArtifactId string `json:"artifactId"`
	// required: true
	// pattern: ^[a-z0-9][a-z0-9_-]*[a-z0-9]$
	// minLength: 8, maxLength: 64
	// Identifier of the application
	AppId string `json:"appId"`
	// required: true
	// application version
	Version string `json:"version"`
	// required: true
	// pattern: ^[\w][\w_-]*[\w]$
	// minLength: 8, maxLength: 128
	// Identifier of the federation
	LeadFederationId string `json:"leadfederationId"`
	// required: true
	// pattern: ^[\w][\w_-]*[\w]$
	// minLength: 8, maxLength: 128
	// Identifier of the federation
	PartnerFederationId string `json:"partnerfederationId"`
	// required: true
	// pattern: ^[\w][\w_-]*[\w]$
	// minLength: 8, maxLength: 32
	// Lead operator identifier
	Operator string `json:"operator"`
	// pattern: ^[A-Z]{2}$
	// ISO 3166-1 Alpha-2 code for the country of Lead operator
	Country string `json:"country"`
}

// Metadata associated with the artifact being uploaded
type ArtifactMetadata struct {
	// enum: ADDED, REMOVED
	// Operation wrt to the notification (Upload or Remove)
	Operation string `json:"operation"`
	// Name of the artifact file (Zip format)
	FileName []byte `json:"filename"`
	// pattern: ^[a-z0-9][a-z0-9_-]*[a-z0-9]$
	// minLength: 8, maxLength: 64
	// Identifier of the application
	AppId string `json:"appId"`
	// Application version
	Version string `json:"version"`
	// enum: ["uploaded", "failed", "deleted"]
	// Status wrt operation
	Status string `json:"status"`
	// Globally unique string used to authenticate operations over federation interface
	LeadFederationId string `json:"leadfederationId"`
	// Globally unique string used to authenticate operations over federation interface
	PartnerFederationId string `json:"partnerfederationId"`
	// Lead operator identifier
	Operator string `json:"operator"`
	// ISO 3166-1 Alpha-2 code for the country of Lead operator
	Country string `json:"country"`
	// Request id for tracking the request over federation interface
	RequestId string `json:"requestId"`
	// pattern: "^[a-z0-9]([a-z0-9]*[a-z0-9])?$"
	// minLength: 1, maxLength: 16
	// Identifier of artifact as received from partner OP
	ArtifactId string `json:"artifactId"`
}

// Application metadata details
type ApplicationMetadata struct {
	// pattern: "^[a-z0-9]([a-z0-9]*[a-z0-9])?$"
	// minLength: 1, maxLength: 16
	// Person who developed the application (developer/ISV)
	DeveloperId string `json:"developerId"`
	// Version of the application in string format
	Version string `json:"version"`
	// Classification of application.
	Category string `jsaon:"category"`
	// Details about application
	AppDescription string `json:"appDescription"`
	// Unique key associated with the application.  This key is used of authentication by client devices
	AccessToken string `json:"accessToken"`
	// enum: ["Allowed", "Not Allowed"]
	// If application supports mobility or not
	MobilitySupport string `json:"mobilitySupport"`
}

// Parameters corresponding to the performance constraints, tenancy details etc
type ApplicationAttributes struct {
	// enum: ["none","low","veryLow"]
	// Latency requirements for the application. Allowed values are none, low and very low. Very Low corresponds to range 15 - 30 msec, Low corresponds to range 30 - 50 msec. None means 51 and above
	LatencyConstraints string `json:"latencyConstraints"`
	// enum: SINGLE, MULTIPLE
	// Define if app supports single user or multiple users
	Tenancy string `json:"tenancy"`
	// If tenancy is multiple, then how many users 1 app can handle
	NoOfUsersPerApp int64 `json:"noOfUsersPerApp"`
	// enum: [0, 1]
	// 0 means all Edges and 1 is single edge
	DeploymentSites int `json:"deploymentSites"`
	// enum: PRIVATE, PUBLIC
	// Define if the application is available for subscription/download by other users/developers
	Visibility string `json:"visibility"`
	// Data transfer bandwidth requirement (minimum limit) for the application. It should in Mbits/sec
	Bandwidth string `json:"bandwidth"`
}

// Geographical location where application should be made available
type Region struct {
	// ISO 3166-1 Alpha-2 code for the country of Lead operator
	Country string `json:"country"`
	// Zone identifier of the operator
	Zone string `json:"zone"`
	// Operator identifier
	Operator string `json:"operator"`
}

// Details of path/docker repository to get component image
type ApplicationComponentSource struct {
	// Defines the source of component container image. If "docker" then component image will be picked from the user provided docker repository. If "file" then component archive will be uploaded from portal or partner OP.
	// enum: ["docker", "file"]
	Repo string `json:"repo"`
	// enum: ["true", "false"]
	// defines the content type of the component source. If "true" then source archive contains the source code to build the component's "docker" image; a valid docker image otherwise. Source code is only applicable for FaaS.
	CodeArchive string `json:"codeArchive"`
	// defines the unique identifier/name of the source archive. It will be platform generated path in case of the user submit the source archive; docker image name otherwise.
	Id string `json:"id"`
	// defines the path/URL of the source archive
	Path string `json:"path"`
	// defines the docker repo username incase external docker repository is used to provide component images
	Username string `json:"username"`
	// defines the docker repo password incase external docker repository is used to provide component images
	Password string `json:"password"`
}

// Details about the terraform and ansible scripts associated with the application
type ApplicationDeployment struct {
	// Name of terraform zip folder containing terraform scripts associate with the application. This is required only when application schema is defined using Terraform
	TerraformFile string `json:"terraformFile"`
	// Name of ansible folder containing ansible scripts associated with the application.
	AnsibleFile string `json:"ansibleFile"`
	// Name of helm folder containing helm chart associated with the application.
	HelmFile string `json:"helmFile"`
}

// List of interfaces exposed by the application component
type ApplicationExposedInterface struct {
	// pattern: "^[a-z0-9]([a-z0-9]*[a-z0-9])?$"
	// minLength: 1, maxLength: 16
	// defines the unique identifier/name of the component's API endpoint. It is a logical API endpoint and will be used to porvide session handle by SDK.
	InterfaceId string `json:"interfaceId"`
	// enum: EVENT, NETWORK
	// Defines the type of interface exposed by the component. This can be event or network.
	InterfaceType string `json:"interfaceType"`
	// pattern: "^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
	// Defines the interface port
	Port string `json:"port"`
	// enum: TCP, UDP, HTTP
	// Defines the network protocol scheme
	Protocol string `json:"protocol"`
	// Defines the upstream path of API endpoint for http-based service component.
	UpstreamPath string `json:"upstreamPath"`
	// enum: ["external", "internal"]
	// defines whether the interface is exposed to outer world or not. If this is set to "internal", then it is not exposed otherwise it is exposed to application component at UE. As of now only "external" is supported.
	Visibility string `json:"visiblity"`
}

// No of GPUs required by the application
type GPUInfo struct {
	// enum: nvidia, amd
	// Types of gpu (Only Nvidia supported)
	GpuType string `json:"gpuType"`
	// Number of gpu
	// minimum: 1, maximum: 4
	NoOfGPUs int `json:"noOfGPUs"`
}

// Details about the minimum CPU, RAM and GPU required by the application
type ApplicationComputeResourceRequirement struct {
	// User defined logical name for the compute resource requirements of the component.
	// pattern: "^[a-z0-9]([a-z0-9]*[a-z0-9])?$"
	// minLength: 1, maxLength: 16
	ResourceProfileId string `json:"resourceProfileId"`
	// Defines the amount of cpu to be allocated to the component (milli CPUs)
	// minimum: 1, maximum: 4
	// multipleOf: 1
	Cpu int64 `json:"cpu"`
	// Defines the amount of memory to be allocated to the component. You can set your memory in 64MB increments from 128MB to 2048MB. Memory is specified in megabytes.
	// minimum: 128, maximum: 2048
	// multipleOf: 64
	Memory int64 `json:"memory"`
	// No of GPUs required by the application
	Gpu GPUInfo `json:"gpu"`
}

// List of key value pairs that will be injected as environment variables in the Kubernetes pod created corresponding the component.
type ApplicationInputParameter struct {
	// pattern: "^[A-Z_]+[A-Z0-9_]*$"
	// minLength: 1, maxLength: 256
	// Environment variable name
	Name string `json:"name"`
	// enum: ["network","constant"]
	// Evnironment variable type
	Type string `json:"type"`
	// minLength: 1, maxLength: 256
	// Environment variable value
	Value string `json:"value"`
}

// Details of persistent volumes required by the application component.
type ApplicationPersistentVolume struct {
	// enum: ["10Gi", "20Gi","50Gi", "100Gi"]
	// size of the volume given by user (10GB, 20GB, 50 GB or 100GB)
	VolumeSize string `json:"volumeSize"`
	// defines the mount path of the volume
	VolumePath string `json:"volumePath"`
	// Human readable name for the volume
	VolumeName string `json:"volumeName"`
}

// Details about different modules of the application
type ApplicationComponent struct {
	// pattern: "^[a-z0-9]([a-z0-9]*[a-z0-9])?$"
	// minLength: 1, maxLength: 16
	// Name of the component
	ComponentId string `json:"componentId"`
	// enum: Kubernetes, VM
	// Define deployment type (Kubernetes-Pods or Virtual Machine) for the application component. Currently only Kubernetes Pods is supported
	VirtualizationMode string `json:"virtualizationMode"`
	// Details of path/docker repository to get component image
	ComponentSource ApplicationComponentSource `json:"componentSource"`
	// List of interfaces exposed by the application component
	ExposedInterfaces ApplicationExposedInterface `json:"exposedInterfaces"`
	// Details about the minimum CPU, RAM and GPU required by the application"
	ComputeResourceRequirements []ApplicationComputeResourceRequirement `json:"ComputeResourceRequirements"`
	// List of key value pairs that will be injected as environment variables in the Kubernetes pod created corresponding the component.
	InputParameters []ApplicationInputParameter `json:"inputParameters"`
	// Details of persistent volumes required by the application component.
	PersistentVolume []ApplicationPersistentVolume `json:"persistentVolume"`
}

// Details about application components, interfaces, executables etc.
type ApplicationComponentDetail struct {
	// pattern: "^[a-z0-9]([a-z0-9]*[a-z0-9])?$"
	// minLength: 1, maxLength: 16
	// User defined identifier for the service. An app can consist of multiple services and is used to generate DNS record for the components in Kubernetes environment. It corresponds to the k8s Service object
	ServiceId string `json:"serviceId"`
	// Details about different modules of the application
	Components []ApplicationComponent `json:"components"`
}

// Details about application components, application images, compute resources etc
type ApplicationSpec struct {
	// Details about the terraform and ansible scripts associated with the application
	Deployment ApplicationDeployment `json:"deployment"`
	// Details about application components, interfaces, executables etc
	ComponentDetails []ApplicationComponentDetail `json:"componentdetails"`
}

type ApplicationData struct {
	// Identifier to track this request over federation interface
	RequestId string `json:"requestId"`
	// Globally unique string to identify an operator platform
	LeadOperatorId string `json:"leadOperatorId"`
	// Globally unique string used to authenticate operations over federation interface
	LeadFederationId string `json:"leadfederationId"`
	// Globally unique string used to authenticate operations over federation interface
	PartnerFederationId string `json:"partnerfederationId"`
	// Identifier of the application
	AppId string `json:"appId"`
	// Can be microservice or faas
	AppType string `json:"appType"`
	// Can be TOSCA, HELM, TERRAFORM, MEC
	AppDescriptorType string `json:"appDescriptorType"`
	// Identifier of artifact associated with the application
	ArtifactId string `json:"artifactId"`
	// Name of the application
	AppName string `json:"appName"`
	// Name of terraform file (zip format). This is required when application schema is defined using Terraform
	TerraformFileId string `json:"terraformFileId"`
	// Name of ansible file (zip format) associated with the application
	AnsibleFileId string `json:"ansibleFileId"`
	// Name of helm file (zip format) associated with the application
	HelmFileId string `json:"helmFileId"`
	// Application metadata details
	Metadata ApplicationMetadata `json:"metadata"`
	// Parameters corresponding to the performance constraints, tenancy details etc
	Attributes ApplicationAttributes `json:"attributes"`
	// default: "Enabled"
	// enum: "Enabled", "Disabled"
	// Define if application can be provisioned or not
	Provisioning string `json:"provisioning"`
	// Geographical location where application should be made available
	Regions []Region `json:"regions"`
	// Details about application components, application images, compute resources etc
	Specification ApplicationSpec `json:"specification"`
}
