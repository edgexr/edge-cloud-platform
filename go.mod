module github.com/edgexr/edge-cloud-infra

go 1.15

require (
	cloud.google.com/go v0.39.0
	github.com/AsGz/geo v0.0.0-20170331085501-324ae0e80045
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/asaskevich/govalidator v0.0.0-20200428143746-21a406dcc535
	github.com/atlassian/go-artifactory/v2 v2.3.0
	github.com/cloudflare/cloudflare-go v0.13.4
	github.com/codeskyblue/go-sh v0.0.0-20170112005953-b097669b1569
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dlclark/regexp2 v1.4.0 // indirect
	github.com/edgexr/edge-cloud v0.0.0-00010101000000-000000000000
	github.com/go-chef/chef v0.23.1
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/go-openapi/errors v0.19.7
	github.com/go-openapi/loads v0.19.5
	github.com/go-openapi/spec v0.19.8
	github.com/go-openapi/strfmt v0.19.5
	github.com/go-openapi/swag v0.19.9
	github.com/go-openapi/validate v0.19.11
	github.com/gogo/googleapis v1.1.0
	github.com/gogo/protobuf v1.3.1
	github.com/google/go-cmp v0.4.0
	github.com/google/uuid v1.1.1
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/gorilla/mux v1.7.4
	github.com/gorilla/websocket v1.4.1
	github.com/hashicorp/go-plugin v1.0.1 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/influxdata/influxdb v1.7.7
	github.com/jaegertracing/jaeger v1.21.0
	github.com/jarcoal/httpmock v1.0.6
	github.com/jinzhu/gorm v1.9.10
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/jung-kurt/gofpdf v1.16.2
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/labstack/echo v0.0.0-20180911044237-1abaa3049251
	github.com/lib/pq v1.5.2
	github.com/miekg/dns v1.1.27
	github.com/mileusna/useragent v1.0.2
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.3.2
	github.com/mobiledgex/golang-ssh v0.0.10
	github.com/mobiledgex/jaeger v1.13.1
	github.com/mobiledgex/yaml/v2 v2.2.5
	github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f
	github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484
	github.com/nmcclain/ldap v0.0.0-20160601145537-6e14e8271933
	github.com/opentracing/opentracing-go v1.1.0
	github.com/pkg/errors v0.9.1
	github.com/pquerna/otp v1.2.1-0.20191009055518-468c2dd2b58d
	github.com/prometheus/client_golang v1.6.0
	github.com/prometheus/common v0.10.0
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/shirou/gopsutil v2.20.4+incompatible
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/test-go/testify v1.1.4
	github.com/tmc/scp v0.0.0-20170824174625-f7b48647feef
	github.com/trustelem/zxcvbn v1.0.1
	github.com/vmware/go-vcloud-director/v2 v2.11.0
	github.com/wcharczuk/go-chart/v2 v2.1.0
	github.com/xanzy/go-gitlab v0.16.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20201010224723-4f7140c49acb
	google.golang.org/api v0.14.0
	google.golang.org/grpc v1.29.1
	gopkg.in/ldap.v3 v3.0.3
	gopkg.in/yaml.v2 v2.3.0
	gortc.io/stun v1.21.0
	//	k8s.io/api v0.0.0-20190327184913-92d2ee7fc726
	k8s.io/api v0.17.3
	k8s.io/apimachinery v0.17.3
	k8s.io/client-go v0.17.3
)

replace github.com/edgexr/edge-cloud => ../edge-cloud

replace (
	github.com/Sirupsen/logrus => github.com/Sirupsen/logrus v1.6.0
	github.com/Sirupsen/logrus v1.6.0 => github.com/sirupsen/logrus v1.6.0
)

replace github.com/vmware/go-vcloud-director/v2 v2.11.0 => github.com/mobiledgex/go-vcloud-director/v2 v2.11.0-241.2

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.1

replace golang.org/x/net => golang.org/x/net v0.0.0-20201010224723-4f7140c49acb

replace github.com/Azure/go-ansiterm => github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78

replace github.com/NYTimes/gziphandler => github.com/NYTimes/gziphandler v1.1.1

replace github.com/Nvveen/Gotty => github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5

replace github.com/OneOfOne/xxhash => github.com/OneOfOne/xxhash v1.2.5

replace github.com/SAP/go-hdb => github.com/SAP/go-hdb v0.14.1

replace github.com/SermoDigital/jose => github.com/SermoDigital/jose v0.9.1

replace github.com/armon/go-radix => github.com/armon/go-radix v1.0.0

replace github.com/bitly/go-hostpool => github.com/bitly/go-hostpool v0.0.0-20171023180738-a3a6125de932

replace github.com/bmizerany/assert => github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869

replace github.com/cespare/xxhash => github.com/cespare/xxhash v1.1.0

replace github.com/codeskyblue/go-sh => github.com/codeskyblue/go-sh v0.0.0-20170112005953-b097669b1569

replace github.com/coreos/bbolt => github.com/coreos/bbolt v1.3.2

replace github.com/coreos/etcd => github.com/coreos/etcd v3.3.10+incompatible

replace github.com/coreos/go-semver => github.com/coreos/go-semver v0.3.0

replace github.com/coreos/pkg => github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f

replace github.com/daviddengcn/go-colortext => github.com/daviddengcn/go-colortext v0.0.0-20171126034257-17e75f6184bc

replace github.com/dgrijalva/jwt-go => github.com/dgrijalva/jwt-go v3.2.0+incompatible

replace github.com/docker/go-connections => github.com/docker/go-connections v0.4.0

replace github.com/duosecurity/duo_api_golang => github.com/duosecurity/duo_api_golang v0.0.0-20190308151101-6c680f768e74

replace github.com/elazarl/go-bindata-assetfs => github.com/elazarl/go-bindata-assetfs v1.0.0

replace github.com/fatih/structs => github.com/fatih/structs v1.1.0

replace github.com/go-ldap/ldap => github.com/go-ldap/ldap v3.0.2+incompatible

replace github.com/gogo/gateway => github.com/gogo/gateway v1.0.0

replace github.com/gogo/googleapis => github.com/gogo/googleapis v1.1.0

replace github.com/golang/protobuf => github.com/golang/protobuf v1.4.2

replace github.com/golangplus/bytes => github.com/golangplus/bytes v0.0.0-20160111154220-45c989fe5450

replace github.com/golangplus/fmt => github.com/golangplus/fmt v0.0.0-20150411045040-2a5d6d7d2995

replace github.com/golangplus/testing => github.com/golangplus/testing v0.0.0-20180327235837-af21d9c3145e

replace github.com/google/go-cmp => github.com/google/go-cmp v0.4.0

replace github.com/gophercloud/gophercloud => github.com/gophercloud/gophercloud v0.8.0

replace github.com/gorilla/websocket => github.com/gorilla/websocket v1.4.1

replace github.com/gotestyourself/gotestyourself => github.com/gotestyourself/gotestyourself v2.2.0+incompatible

replace github.com/grpc-ecosystem/go-grpc-middleware => github.com/grpc-ecosystem/go-grpc-middleware v1.2.0

replace github.com/grpc-ecosystem/grpc-gateway => github.com/grpc-ecosystem/grpc-gateway v1.14.5

replace github.com/hashicorp/vault => github.com/hashicorp/vault v1.4.2

replace github.com/influxdata/influxdb => github.com/influxdata/influxdb v1.7.7

replace github.com/jefferai/jsonx => github.com/jefferai/jsonx v1.0.0

replace github.com/keybase/go-crypto => github.com/keybase/go-crypto v0.0.0-20190403132359-d65b6b94177f

replace github.com/mitchellh/copystructure => github.com/mitchellh/copystructure v1.0.0

replace github.com/mitchellh/mapstructure => github.com/mobiledgex/mapstructure v1.2.4-0.20200429201435-a2efef9031f5

replace github.com/opencontainers/go-digest => github.com/opencontainers/go-digest v1.0.0-rc1

replace github.com/opencontainers/image-spec => github.com/opencontainers/image-spec v1.0.1

replace github.com/opencontainers/runc => github.com/opencontainers/runc v0.1.1

replace github.com/patrickmn/go-cache => github.com/patrickmn/go-cache v2.1.0+incompatible

replace github.com/spaolacci/murmur3 => github.com/spaolacci/murmur3 v1.1.0

replace github.com/spf13/cobra => github.com/spf13/cobra v0.0.5

replace github.com/spf13/pflag => github.com/spf13/pflag v1.0.5

replace github.com/stretchr/testify => github.com/stretchr/testify v1.7.0

replace github.com/tmc/grpc-websocket-proxy => github.com/tmc/grpc-websocket-proxy v0.0.0-20190109142713-0ad062ec5ee5

replace go.uber.org/zap => go.uber.org/zap v1.16.0

replace golang.org/x/crypto => golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9

replace google.golang.org/genproto => google.golang.org/genproto v0.0.0-20200305110556-506484158171

replace google.golang.org/grpc => google.golang.org/grpc v1.29.1

replace gopkg.in/asn1-ber.v1 => gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d

replace gopkg.in/mgo.v2 => gopkg.in/mgo.v2 v2.0.0-20180705113604-9856a29383ce

replace gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.3.0

replace gotest.tools => gotest.tools v2.2.0+incompatible

replace k8s.io/api => k8s.io/api v0.17.3

replace k8s.io/apimachinery => k8s.io/apimachinery v0.17.3

replace k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20190313123343-44a48934c135

replace k8s.io/client-go => k8s.io/client-go v0.17.3

replace github.com/mobiledgex/yaml/v2 => github.com/mobiledgex/yaml/v2 v2.2.5

replace github.com/opentracing/opentracing-go => github.com/opentracing/opentracing-go v1.1.0

replace github.com/uber/jaeger-client-go => github.com/uber/jaeger-client-go v2.23.1+incompatible

replace github.com/denisenkom/go-mssqldb => github.com/denisenkom/go-mssqldb v0.0.0-20190905012053-7920e8ef8898

replace github.com/google/go-github => github.com/google/go-github v17.0.0+incompatible

replace github.com/google/go-querystring => github.com/google/go-querystring v1.0.0

replace github.com/prometheus/common => github.com/prometheus/common v0.10.0

replace github.com/uber-go/atomic => github.com/uber-go/atomic v1.4.0

replace github.com/xtaci/smux => github.com/xtaci/smux v1.3.6

replace github.com/segmentio/ksuid => github.com/segmentio/ksuid v1.0.2

replace github.com/docker/docker => github.com/docker/docker v1.13.1

replace github.com/jcelliott/lumber => github.com/jcelliott/lumber v0.0.0-20160324203708-dd349441af25

replace github.com/mobiledgex/golang-ssh => github.com/mobiledgex/golang-ssh v0.0.10

replace github.com/elastic/go-elasticsearch/v7 => github.com/elastic/go-elasticsearch/v7 v7.5.0

replace github.com/armon/go-metrics => github.com/armon/go-metrics v0.3.3

replace github.com/asaskevich/govalidator => github.com/asaskevich/govalidator v0.0.0-20200428143746-21a406dcc535

replace github.com/cenkalti/backoff => github.com/cenkalti/backoff v2.2.1+incompatible

replace github.com/codahale/hdrhistogram => github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd

replace github.com/docker/go-units => github.com/docker/go-units v0.4.0

replace github.com/frankban/quicktest => github.com/frankban/quicktest v1.10.0

replace github.com/go-sql-driver/mysql => github.com/go-sql-driver/mysql v1.5.0

replace github.com/grpc-ecosystem/go-grpc-prometheus => github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0

replace github.com/hashicorp/go-rootcerts => github.com/hashicorp/go-rootcerts v1.0.2

replace github.com/hashicorp/go-sockaddr => github.com/hashicorp/go-sockaddr v1.0.2

replace github.com/hashicorp/go-version => github.com/hashicorp/go-version v1.2.1

replace github.com/jonboulle/clockwork => github.com/jonboulle/clockwork v0.1.0

replace github.com/pierrec/lz4 => github.com/pierrec/lz4 v2.5.2+incompatible

replace github.com/soheilhy/cmux => github.com/soheilhy/cmux v0.1.4

replace github.com/xiang90/probing => github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2

replace go.etcd.io/bbolt => go.etcd.io/bbolt v1.3.5

replace github.com/pkg/errors => github.com/pkg/errors v0.9.1

replace github.com/golang/snappy => github.com/golang/snappy v0.0.1

replace github.com/prometheus/client_golang => github.com/prometheus/client_golang v1.6.0

replace github.com/go-openapi/errors => github.com/go-openapi/errors v0.19.7

replace github.com/go-openapi/strfmt => github.com/go-openapi/strfmt v0.19.5

replace github.com/go-openapi/swag => github.com/go-openapi/swag v0.19.9

replace github.com/go-openapi/validate => github.com/go-openapi/validate v0.19.11

replace github.com/creack/pty => github.com/creack/pty v1.1.10

replace github.com/jarcoal/httpmock => github.com/jarcoal/httpmock v1.0.6

replace github.com/go-chef/chef => github.com/go-chef/chef v0.23.1

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v1.0.5-0.20200317185738-82f498082f02

replace github.com/cloudflare/cloudflare-go => github.com/cloudflare/cloudflare-go v0.13.4

replace github.com/jaegertracing/jaeger => github.com/jaegertracing/jaeger v1.21.0

replace github.com/uber/jaeger-lib => github.com/uber/jaeger-lib v2.4.0+incompatible

replace cloud.google.com/go => cloud.google.com/go v0.39.0

replace google.golang.org/api => google.golang.org/api v0.14.0

replace golang.org/x/oauth2 => golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45

replace github.com/Shopify/sarama => github.com/Shopify/sarama v1.22.2-0.20190604114437-cd910a683f9f

replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f

replace golang.org/x/time => golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e

replace github.com/davecgh/go-spew => github.com/davecgh/go-spew v1.1.1

replace github.com/go-redis/redis => github.com/go-redis/redis v6.15.9+incompatible

replace github.com/agnivade/levenshtein => github.com/agnivade/levenshtein v1.0.1

replace github.com/test-go/testify => github.com/test-go/testify v1.1.4

replace golang.org/x/tools => golang.org/x/tools v0.0.0-20200603131246-cc40288be839

replace github.com/Bose/minisentinel => github.com/Bose/minisentinel v0.0.0-20200130220412-917c5a9223bb

replace github.com/alicebob/miniredis/v2 => github.com/alicebob/miniredis/v2 v2.18.0

replace github.com/gomodule/redigo => github.com/gomodule/redigo v1.8.8

replace github.com/yuin/gopher-lua => github.com/yuin/gopher-lua v0.0.0-20210529063254-f4c35e4016d9

replace github.com/kballard/go-shellquote => github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
