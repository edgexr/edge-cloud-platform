module github.com/mobiledgex/edge-cloud-infra

go 1.12

require (
	cloud.google.com/go v0.37.4 // indirect
	github.com/AsGz/geo v0.0.0-20170331085501-324ae0e80045
	github.com/asaskevich/govalidator v0.0.0-20200428143746-21a406dcc535
	github.com/atlassian/go-artifactory/v2 v2.3.0
	github.com/cloudflare/cloudflare-go v0.8.5
	github.com/codeskyblue/go-sh v0.0.0-20170112005953-b097669b1569
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/machine v0.16.1 // indirect
	github.com/elazarl/goproxy v0.0.0-20190410145444-c548f45dcf1d // indirect
	github.com/elazarl/goproxy/ext v0.0.0-20190410145444-c548f45dcf1d // indirect
	github.com/fsouza/go-dockerclient v1.3.6
	github.com/go-chef/chef v0.20.1
	github.com/go-openapi/errors v0.19.6
	github.com/go-openapi/strfmt v0.19.5
	github.com/go-openapi/swag v0.19.9
	github.com/go-openapi/validate v0.19.10
	github.com/go-resty/resty/v2 v2.0.0
	github.com/gogo/googleapis v1.0.0
	github.com/gogo/protobuf v1.2.1
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.4.0
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/gophercloud/gophercloud v0.0.0-20190330013820-4d3066f119fa
	github.com/gorilla/mux v1.7.0
	github.com/gorilla/websocket v1.4.0
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.8.5
	github.com/hashicorp/vault v0.11.5
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/influxdata/influxdb v1.6.2
	github.com/jaegertracing/jaeger v1.13.1
	github.com/jarcoal/httpmock v1.0.4
	github.com/jinzhu/gorm v1.9.10
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/json-iterator/go v1.1.6 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/kennygrant/sanitize v1.2.4
	github.com/labstack/echo v0.0.0-20180911044237-1abaa3049251
	github.com/lib/pq v1.1.1
	github.com/miekg/dns v1.1.15
	github.com/mitchellh/mapstructure v1.3.2
	github.com/mobiledgex/edge-cloud v1.0.1
	github.com/mobiledgex/golang-ssh v0.0.10
	github.com/mobiledgex/yaml/v2 v2.2.5
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/moul/http2curl v1.0.0 // indirect
	github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f
	github.com/nbutton23/zxcvbn-go v0.0.0-20180912185939-ae427f1e4c1d
	github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484
	github.com/nmcclain/ldap v0.0.0-20160601145537-6e14e8271933
	github.com/opentracing/opentracing-go v1.1.0
	github.com/parnurzeal/gorequest v0.2.15
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/pion/webrtc/v2 v2.0.24
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.3-0.20190127221311-3c4408c8b829
	github.com/prometheus/common v0.0.0-20181218105931-67670fe90761
	github.com/shirou/gopsutil v2.18.12+incompatible
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.4
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.6.1
	github.com/tmc/scp v0.0.0-20170824174625-f7b48647feef
	github.com/xanzy/go-gitlab v0.16.0
	golang.org/x/crypto v0.0.0-20190617133340-57b3e21c3d56
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	golang.org/x/tools v0.0.0-20190617190820-da514acc4774 // indirect
	google.golang.org/genproto v0.0.0-20190404172233-64821d5d2107
	google.golang.org/grpc v1.22.0
	gopkg.in/ldap.v3 v3.0.3
	gopkg.in/yaml.v2 v2.3.0
	gortc.io/stun v1.21.0
	gotest.tools v2.2.0+incompatible
	//	k8s.io/api v0.0.0-20190327184913-92d2ee7fc726
	k8s.io/api v0.0.0-20190222213804-5cb15d344471
	k8s.io/apimachinery v0.0.0-20190402064448-91ffda0f6be2
	k8s.io/client-go v0.0.0-20180517072830-4bb327ea2f8e
)

replace github.com/mobiledgex/edge-cloud => ../edge-cloud

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.0.0

replace golang.org/x/net => golang.org/x/net v0.0.0-20190628185345-da137c7871d7

replace github.com/Azure/go-ansiterm => github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78

replace github.com/Microsoft/go-winio => github.com/Microsoft/go-winio v0.4.12

replace github.com/NYTimes/gziphandler => github.com/NYTimes/gziphandler v1.1.1

replace github.com/Nvveen/Gotty => github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5

replace github.com/OneOfOne/xxhash => github.com/OneOfOne/xxhash v1.2.5

replace github.com/SAP/go-hdb => github.com/SAP/go-hdb v0.14.1

replace github.com/SermoDigital/jose => github.com/SermoDigital/jose v0.9.1

replace github.com/armon/go-metrics => github.com/armon/go-metrics v0.0.0-20180917152333-f0300d1749da

replace github.com/armon/go-radix => github.com/armon/go-radix v1.0.0

replace github.com/asaskevich/govalidator => github.com/asaskevich/govalidator v0.0.0-20180720115003-f9ffefc3facf

replace github.com/bitly/go-hostpool => github.com/bitly/go-hostpool v0.0.0-20171023180738-a3a6125de932

replace github.com/bmizerany/assert => github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869

replace github.com/cenkalti/backoff => github.com/cenkalti/backoff v2.1.1+incompatible

replace github.com/cespare/xxhash => github.com/cespare/xxhash v1.0.0

replace github.com/codegangsta/inject => github.com/codegangsta/inject v0.0.0-20140425184007-37d7f8432a3e

replace github.com/codeskyblue/go-sh => github.com/codeskyblue/go-sh v0.0.0-20170112005953-b097669b1569

replace github.com/containerd/continuity => github.com/containerd/continuity v0.0.0-20181203112020-004b46473808

replace github.com/coreos/bbolt => github.com/coreos/bbolt v1.3.2

replace github.com/coreos/etcd => github.com/coreos/etcd v3.3.10+incompatible

replace github.com/coreos/go-semver => github.com/coreos/go-semver v0.3.0

replace github.com/coreos/pkg => github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f

replace github.com/daviddengcn/go-colortext => github.com/daviddengcn/go-colortext v0.0.0-20171126034257-17e75f6184bc

replace github.com/dgrijalva/jwt-go => github.com/dgrijalva/jwt-go v3.2.0+incompatible

replace github.com/docker/go-connections => github.com/docker/go-connections v0.4.0

replace github.com/docker/go-units => github.com/docker/go-units v0.3.3

replace github.com/duosecurity/duo_api_golang => github.com/duosecurity/duo_api_golang v0.0.0-20190308151101-6c680f768e74

replace github.com/elazarl/go-bindata-assetfs => github.com/elazarl/go-bindata-assetfs v1.0.0

replace github.com/fatih/structs => github.com/fatih/structs v1.1.0

replace github.com/ghodss/yaml => github.com/ghodss/yaml v1.0.0

replace github.com/go-ldap/ldap => github.com/go-ldap/ldap v3.0.2+incompatible

replace github.com/go-sql-driver/mysql => github.com/go-sql-driver/mysql v1.4.1

replace github.com/go-test/deep => github.com/go-test/deep v1.0.1

replace github.com/gocql/gocql => github.com/gocql/gocql v0.0.0-20190402132108-0e1d5de854df

replace github.com/gogo/gateway => github.com/gogo/gateway v1.0.0

replace github.com/gogo/googleapis => github.com/gogo/googleapis v1.0.0

replace github.com/golang/groupcache => github.com/golang/groupcache v0.0.0-20190129154638-5b532d6fd5ef

replace github.com/golang/protobuf => github.com/golang/protobuf v1.3.1

replace github.com/golangplus/bytes => github.com/golangplus/bytes v0.0.0-20160111154220-45c989fe5450

replace github.com/golangplus/fmt => github.com/golangplus/fmt v0.0.0-20150411045040-2a5d6d7d2995

replace github.com/golangplus/testing => github.com/golangplus/testing v0.0.0-20180327235837-af21d9c3145e

replace github.com/google/btree => github.com/google/btree v0.0.0-20180813153112-4030bb1f1f0c

replace github.com/google/go-cmp => github.com/google/go-cmp v0.2.1-0.20190312032427-6f77996f0c42

replace github.com/google/gofuzz => github.com/google/gofuzz v0.0.0-20170612174753-24818f796faf

replace github.com/gophercloud/gophercloud => github.com/gophercloud/gophercloud v0.0.0-20180531020630-7112fcd50da4

replace github.com/gorilla/websocket => github.com/gorilla/websocket v1.4.0

replace github.com/gotestyourself/gotestyourself => github.com/gotestyourself/gotestyourself v2.2.0+incompatible

replace github.com/grpc-ecosystem/go-grpc-middleware => github.com/grpc-ecosystem/go-grpc-middleware v1.0.0

replace github.com/grpc-ecosystem/go-grpc-prometheus => github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0

replace github.com/grpc-ecosystem/grpc-gateway => github.com/grpc-ecosystem/grpc-gateway v1.6.2

replace github.com/hashicorp/go-hclog => github.com/hashicorp/go-hclog v0.8.0

replace github.com/hashicorp/go-memdb => github.com/hashicorp/go-memdb v1.0.0

replace github.com/hashicorp/go-multierror => github.com/hashicorp/go-multierror v1.0.0

replace github.com/hashicorp/go-plugin => github.com/hashicorp/go-plugin v1.0.0

replace github.com/hashicorp/go-retryablehttp => github.com/hashicorp/go-retryablehttp v0.5.0

replace github.com/hashicorp/go-rootcerts => github.com/hashicorp/go-rootcerts v0.0.0-20160503143440-6bb64b370b90

replace github.com/hashicorp/go-sockaddr => github.com/hashicorp/go-sockaddr v1.0.0

replace github.com/hashicorp/go-uuid => github.com/hashicorp/go-uuid v1.0.1

replace github.com/hashicorp/go-version => github.com/hashicorp/go-version v1.1.0

replace github.com/hashicorp/golang-lru => github.com/hashicorp/golang-lru v0.5.1

replace github.com/hashicorp/vault => github.com/hashicorp/vault v0.11.5

replace github.com/hashicorp/vault-plugin-secrets-kv => github.com/hashicorp/vault-plugin-secrets-kv v0.0.0-20190404212640-4807e6564154

replace github.com/influxdata/influxdb => github.com/influxdata/influxdb v1.6.2

replace github.com/jefferai/jsonx => github.com/jefferai/jsonx v1.0.0

replace github.com/jonboulle/clockwork => github.com/jonboulle/clockwork v0.1.0

replace github.com/json-iterator/go => github.com/json-iterator/go v0.0.0-20180315132816-ca39e5af3ece

replace github.com/keybase/go-crypto => github.com/keybase/go-crypto v0.0.0-20190403132359-d65b6b94177f

replace github.com/kr/pretty => github.com/kr/pretty v0.1.0

replace github.com/lib/pq => github.com/lib/pq v1.0.0

replace github.com/mitchellh/copystructure => github.com/mitchellh/copystructure v1.0.0

replace github.com/mitchellh/go-testing-interface => github.com/mitchellh/go-testing-interface v1.0.0

replace github.com/mitchellh/mapstructure => github.com/mobiledgex/mapstructure v1.2.4-0.20200429201435-a2efef9031f5

replace github.com/modern-go/concurrent => github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd

replace github.com/modern-go/reflect2 => github.com/modern-go/reflect2 v0.0.0-20180228065516-1df9eeb2bb81

replace github.com/opencontainers/go-digest => github.com/opencontainers/go-digest v1.0.0-rc1

replace github.com/opencontainers/image-spec => github.com/opencontainers/image-spec v1.0.1

replace github.com/opencontainers/runc => github.com/opencontainers/runc v0.1.1

replace github.com/ory/dockertest => github.com/ory/dockertest v3.3.4+incompatible

replace github.com/pascaldekloe/goe => github.com/pascaldekloe/goe v0.1.0

replace github.com/patrickmn/go-cache => github.com/patrickmn/go-cache v2.1.0+incompatible

replace github.com/prometheus/client_model => github.com/prometheus/client_model v0.0.0-20190129233127-fd36f4220a90

replace github.com/prometheus/procfs => github.com/prometheus/procfs v0.0.0-20190117184657-bf6a532e95b1

replace github.com/ryanuber/go-glob => github.com/ryanuber/go-glob v0.0.0-20160226084822-572520ed46db

replace github.com/sirupsen/logrus => github.com/sirupsen/logrus v1.2.0

replace github.com/soheilhy/cmux => github.com/soheilhy/cmux v0.1.4

replace github.com/spaolacci/murmur3 => github.com/spaolacci/murmur3 v1.1.0

replace github.com/spf13/cobra => github.com/spf13/cobra v0.0.4

replace github.com/spf13/pflag => github.com/spf13/pflag v1.0.3

replace github.com/stretchr/testify => github.com/stretchr/testify v1.6.0

replace github.com/tmc/grpc-websocket-proxy => github.com/tmc/grpc-websocket-proxy v0.0.0-20190109142713-0ad062ec5ee5

replace github.com/xiang90/probing => github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2

replace go.etcd.io/bbolt => go.etcd.io/bbolt v1.3.2

replace go.uber.org/multierr => go.uber.org/multierr v1.1.0

replace go.uber.org/zap => go.uber.org/zap v1.10.0

replace golang.org/x/crypto => golang.org/x/crypto v0.0.0-20190426145343-a29dc8fdc734

replace golang.org/x/oauth2 => golang.org/x/oauth2 v0.0.0-20190226205417-e64efc72b421

replace golang.org/x/time => golang.org/x/time v0.0.0-20181108054448-85acf8d2951c

replace google.golang.org/genproto => google.golang.org/genproto v0.0.0-20190307195333-5fe7a883aa19

replace google.golang.org/grpc => google.golang.org/grpc v1.21.0

replace gopkg.in/asn1-ber.v1 => gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d

replace gopkg.in/mgo.v2 => gopkg.in/mgo.v2 v2.0.0-20180705113604-9856a29383ce

replace gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.2

replace gotest.tools => gotest.tools v2.2.0+incompatible

replace k8s.io/api => k8s.io/api v0.0.0-20190222213804-5cb15d344471

replace k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20180516022032-3492ef8dace1

replace k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20190313123343-44a48934c135

replace k8s.io/client-go => k8s.io/client-go v0.0.0-20180517072830-4bb327ea2f8e

replace sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0

replace github.com/mobiledgex/yaml/v2 => github.com/mobiledgex/yaml/v2 v2.2.5

replace github.com/kr/pty => github.com/kr/pty v1.1.3

replace github.com/pion/webrtc/v2 => github.com/pion/webrtc/v2 v2.0.24

replace golang.org/x/text => golang.org/x/text v0.3.1-0.20180807135948-17ff2d5776d2

replace github.com/opentracing/opentracing-go => github.com/opentracing/opentracing-go v1.1.0

replace github.com/uber/jaeger-client-go => github.com/uber/jaeger-client-go v2.16.1-0.20190705220040-402bec9e6ead+incompatible

replace github.com/uber/jaeger-lib => github.com/uber/jaeger-lib v2.0.0+incompatible

replace github.com/codahale/hdrhistogram => github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd

replace github.com/coreos/go-systemd => github.com/coreos/go-systemd v0.0.0-20181012123002-c6f51f82210d

replace github.com/denisenkom/go-mssqldb => github.com/denisenkom/go-mssqldb v0.0.0-20190905012053-7920e8ef8898

replace github.com/golang/snappy => github.com/golang/snappy v0.0.0-20180518054509-2e65f85255db

replace github.com/google/go-github => github.com/google/go-github v17.0.0+incompatible

replace github.com/google/go-querystring => github.com/google/go-querystring v1.0.0

replace github.com/pierrec/lz4 => github.com/pierrec/lz4 v2.0.5+incompatible

replace github.com/prometheus/client_golang => github.com/prometheus/client_golang v0.9.2

replace github.com/prometheus/common => github.com/prometheus/common v0.0.0-20181218105931-67670fe90761

replace github.com/uber-go/atomic => github.com/uber-go/atomic v1.4.0

replace go.uber.org/atomic => go.uber.org/atomic v1.4.0

replace gopkg.in/check.v1 => gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127

replace github.com/xtaci/smux => github.com/xtaci/smux v1.3.6

replace github.com/segmentio/ksuid => github.com/segmentio/ksuid v1.0.2

replace github.com/docker/docker => github.com/docker/docker v1.13.1

replace github.com/golang/glog => github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b

replace github.com/jcelliott/lumber => github.com/jcelliott/lumber v0.0.0-20160324203708-dd349441af25

replace github.com/mobiledgex/golang-ssh => github.com/mobiledgex/golang-ssh v0.0.10

replace github.com/rogpeppe/fastuuid => github.com/rogpeppe/fastuuid v1.2.0

replace gopkg.in/yaml.v3 => gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c

replace github.com/elastic/go-elasticsearch/v7 => github.com/elastic/go-elasticsearch/v7 v7.5.0
