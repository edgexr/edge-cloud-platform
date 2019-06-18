module github.com/mobiledgex/edge-cloud-infra

go 1.12

require (
	github.com/asaskevich/govalidator v0.0.0-20180720115003-f9ffefc3facf
	github.com/atlassian/go-artifactory/v2 v2.3.0
	github.com/casbin/casbin v1.6.0
	github.com/casbin/gorm-adapter v0.0.0-20171006093545-e56c6daebd5e
	github.com/cloudflare/cloudflare-go v0.8.5
	github.com/codeskyblue/go-sh v0.0.0-20170112005953-b097669b1569
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e // indirect
	github.com/denisenkom/go-mssqldb v0.0.0-20190515213511-eb9f6a1743f3 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/cli v0.0.0-20190520121752-57aa7731d0a5
	github.com/docker/machine v0.16.1 // indirect
	github.com/elazarl/goproxy v0.0.0-20190410145444-c548f45dcf1d // indirect
	github.com/elazarl/goproxy/ext v0.0.0-20190410145444-c548f45dcf1d // indirect
	github.com/fsouza/go-dockerclient v1.3.6
	github.com/ghodss/yaml v1.0.0
	github.com/gogo/googleapis v1.0.0
	github.com/gogo/protobuf v1.2.0
	github.com/golang/protobuf v1.3.1
	github.com/google/go-cmp v0.2.1-0.20190312032427-6f77996f0c42
	github.com/gophercloud/gophercloud v0.0.0-20190330013820-4d3066f119fa
	github.com/grpc-ecosystem/grpc-gateway v1.8.5
	github.com/influxdata/influxdb v1.6.2
	github.com/jcelliott/lumber v0.0.0-20160324203708-dd349441af25 // indirect
	github.com/jinzhu/gorm v1.9.1
	github.com/json-iterator/go v1.1.6 // indirect
	github.com/julienschmidt/httprouter v1.2.0
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/labstack/echo v0.0.0-20180911044237-1abaa3049251
	github.com/lib/pq v1.0.0
	github.com/mitchellh/mapstructure v1.1.2
	github.com/mobiledgex/edge-cloud v1.0.1
	github.com/mobiledgex/golang-ssh v0.0.2
	github.com/mobiledgex/yaml v2.1.0+incompatible
	github.com/mobiledgex/yaml/v2 v2.2.4
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/moul/http2curl v1.0.0 // indirect
	github.com/nanobox-io/golang-ssh v0.0.0-20190309194042-12ea65d3a59d
	github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484
	github.com/nmcclain/ldap v0.0.0-20160601145537-6e14e8271933
	github.com/parnurzeal/gorequest v0.2.15
	github.com/pelletier/go-toml v1.3.0
	github.com/pion/webrtc/v2 v2.0.7
	github.com/sirupsen/logrus v1.4.1
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a // indirect
	github.com/spf13/cobra v0.0.4
	github.com/stretchr/testify v1.3.0
	github.com/xanzy/go-gitlab v0.16.0
	go.uber.org/zap v1.10.0
	golang.org/x/crypto v0.0.0-20190404164418-38d8ce5564a5
	golang.org/x/net v0.0.0-20190328230028-74de082e2cca
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	google.golang.org/genproto v0.0.0-20190404172233-64821d5d2107
	google.golang.org/grpc v1.21.0
	gopkg.in/ldap.v3 v3.0.3
	gopkg.in/yaml.v2 v2.2.2
	//	k8s.io/api v0.0.0-20190327184913-92d2ee7fc726
	k8s.io/api v0.0.0-20190222213804-5cb15d344471
	k8s.io/apimachinery v0.0.0-20190402064448-91ffda0f6be2
	k8s.io/client-go v0.0.0-20180517072830-4bb327ea2f8e
	k8s.io/klog v0.2.0 // indirect
	k8s.io/kubernetes v1.14.1
)

replace github.com/mobiledgex/edge-cloud => ../edge-cloud

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.0.0

replace golang.org/x/net => golang.org/x/net v0.0.0-20190311183353-d8887717615a

replace github.com/AsGz/geo => github.com/AsGz/geo v0.0.0-20170331085501-324ae0e80045

replace github.com/Azure/go-ansiterm => github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78

replace github.com/Knetic/govaluate => github.com/Knetic/govaluate v3.0.0+incompatible

replace github.com/Microsoft/go-winio => github.com/Microsoft/go-winio v0.4.12

replace github.com/NYTimes/gziphandler => github.com/NYTimes/gziphandler v1.1.1

replace github.com/Nvveen/Gotty => github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5

replace github.com/OneOfOne/xxhash => github.com/OneOfOne/xxhash v1.2.5

replace github.com/SAP/go-hdb => github.com/SAP/go-hdb v0.14.1

replace github.com/SermoDigital/jose => github.com/SermoDigital/jose v0.9.1

replace github.com/Shopify/toxiproxy => github.com/Shopify/toxiproxy v2.1.4+incompatible

replace github.com/alecthomas/template => github.com/alecthomas/template v0.0.0-20160405071501-a0175ee3bccc

replace github.com/alecthomas/units => github.com/alecthomas/units v0.0.0-20151022065526-2efee857e7cf

replace github.com/apache/thrift => github.com/apache/thrift v0.12.0

replace github.com/armon/go-metrics => github.com/armon/go-metrics v0.0.0-20180917152333-f0300d1749da

replace github.com/armon/go-radix => github.com/armon/go-radix v1.0.0

replace github.com/asaskevich/govalidator => github.com/asaskevich/govalidator v0.0.0-20180720115003-f9ffefc3facf

replace github.com/bitly/go-hostpool => github.com/bitly/go-hostpool v0.0.0-20171023180738-a3a6125de932

replace github.com/bmizerany/assert => github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869

replace github.com/casbin/casbin => github.com/casbin/casbin v1.6.0

replace github.com/casbin/gorm-adapter => github.com/casbin/gorm-adapter v0.0.0-20171006093545-e56c6daebd5e

replace github.com/cenkalti/backoff => github.com/cenkalti/backoff v2.1.1+incompatible

replace github.com/cespare/xxhash => github.com/cespare/xxhash v1.0.0

replace github.com/cloudflare/cloudflare-go => github.com/cloudflare/cloudflare-go v0.8.5

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

replace github.com/erikstmartin/go-testdb => github.com/erikstmartin/go-testdb v0.0.0-20160219214506-8d10e4a1bae5

replace github.com/fatih/structs => github.com/fatih/structs v1.1.0

replace github.com/ghodss/yaml => github.com/ghodss/yaml v1.0.0

replace github.com/go-kit/kit => github.com/go-kit/kit v0.8.0

replace github.com/go-ldap/ldap => github.com/go-ldap/ldap v3.0.2+incompatible

replace github.com/go-logfmt/logfmt => github.com/go-logfmt/logfmt v0.3.0

replace github.com/go-sql-driver/mysql => github.com/go-sql-driver/mysql v1.4.1

replace github.com/go-stack/stack => github.com/go-stack/stack v1.8.0

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

replace github.com/google/pprof => github.com/google/pprof v0.0.0-20181206194817-3ea8567a2e57

replace github.com/googleapis/gax-go/v2 => github.com/googleapis/gax-go/v2 v2.0.4

replace github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.1.0

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

replace github.com/hashicorp/hcl => github.com/hashicorp/hcl v1.0.0

replace github.com/hashicorp/vault => github.com/hashicorp/vault v0.11.5

replace github.com/hashicorp/vault-plugin-secrets-kv => github.com/hashicorp/vault-plugin-secrets-kv v0.0.0-20190404212640-4807e6564154

replace github.com/imdario/mergo => github.com/imdario/mergo v0.3.4

replace github.com/inconshreveable/mousetrap => github.com/inconshreveable/mousetrap v1.0.0

replace github.com/influxdata/influxdb => github.com/influxdata/influxdb v1.6.2

replace github.com/jefferai/jsonx => github.com/jefferai/jsonx v1.0.0

replace github.com/jinzhu/gorm => github.com/jinzhu/gorm v1.9.1

replace github.com/jinzhu/inflection => github.com/jinzhu/inflection v0.0.0-20180308033659-04140366298a

replace github.com/jinzhu/now => github.com/jinzhu/now v1.0.0

replace github.com/jonboulle/clockwork => github.com/jonboulle/clockwork v0.1.0

replace github.com/json-iterator/go => github.com/json-iterator/go v0.0.0-20180315132816-ca39e5af3ece

replace github.com/jstemmer/go-junit-report => github.com/jstemmer/go-junit-report v0.0.0-20190106144839-af01ea7f8024

replace github.com/julienschmidt/httprouter => github.com/julienschmidt/httprouter v1.2.0

replace github.com/keybase/go-crypto => github.com/keybase/go-crypto v0.0.0-20190403132359-d65b6b94177f

replace github.com/kr/logfmt => github.com/kr/logfmt v0.0.0-20140226030751-b84e30acd515

replace github.com/kr/pretty => github.com/kr/pretty v0.1.0

replace github.com/labstack/echo => github.com/labstack/echo v0.0.0-20180911044237-1abaa3049251

replace github.com/labstack/gommon => github.com/labstack/gommon v0.2.7

replace github.com/lib/pq => github.com/lib/pq v1.0.0

replace github.com/mattn/go-isatty => github.com/mattn/go-isatty v0.0.4

replace github.com/mattn/go-sqlite3 => github.com/mattn/go-sqlite3 v1.10.0

replace github.com/mitchellh/copystructure => github.com/mitchellh/copystructure v1.0.0

replace github.com/mitchellh/go-testing-interface => github.com/mitchellh/go-testing-interface v1.0.0

replace github.com/mitchellh/mapstructure => github.com/mitchellh/mapstructure v1.1.2

replace github.com/modern-go/concurrent => github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd

replace github.com/modern-go/reflect2 => github.com/modern-go/reflect2 v0.0.0-20180228065516-1df9eeb2bb81

replace github.com/mwitkow/go-conntrack => github.com/mwitkow/go-conntrack v0.0.0-20161129095857-cc309e4a2223

replace github.com/nmcclain/asn1-ber => github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484

replace github.com/nmcclain/ldap => github.com/nmcclain/ldap v0.0.0-20160601145537-6e14e8271933

replace github.com/opencontainers/go-digest => github.com/opencontainers/go-digest v1.0.0-rc1

replace github.com/opencontainers/image-spec => github.com/opencontainers/image-spec v1.0.1

replace github.com/opencontainers/runc => github.com/opencontainers/runc v0.1.1

replace github.com/openzipkin/zipkin-go => github.com/openzipkin/zipkin-go v0.1.5

replace github.com/ory/dockertest => github.com/ory/dockertest v3.3.4+incompatible

replace github.com/pascaldekloe/goe => github.com/pascaldekloe/goe v0.1.0

replace github.com/patrickmn/go-cache => github.com/patrickmn/go-cache v2.1.0+incompatible

replace github.com/peterbourgon/diskv => github.com/peterbourgon/diskv v2.0.1+incompatible

replace github.com/prometheus/client_model => github.com/prometheus/client_model v0.0.0-20190129233127-fd36f4220a90

replace github.com/prometheus/procfs => github.com/prometheus/procfs v0.0.0-20190117184657-bf6a532e95b1

replace github.com/ryanuber/go-glob => github.com/ryanuber/go-glob v0.0.0-20160226084822-572520ed46db

replace github.com/sirupsen/logrus => github.com/sirupsen/logrus v1.2.0

replace github.com/soheilhy/cmux => github.com/soheilhy/cmux v0.1.4

replace github.com/spaolacci/murmur3 => github.com/spaolacci/murmur3 v1.1.0

replace github.com/spf13/cobra => github.com/spf13/cobra v0.0.4

replace github.com/spf13/pflag => github.com/spf13/pflag v1.0.3

replace github.com/stretchr/testify => github.com/stretchr/testify v1.3.0

replace github.com/tmc/grpc-websocket-proxy => github.com/tmc/grpc-websocket-proxy v0.0.0-20190109142713-0ad062ec5ee5

replace github.com/ugorji/go => github.com/ugorji/go v1.1.4

replace github.com/valyala/bytebufferpool => github.com/valyala/bytebufferpool v1.0.0

replace github.com/xanzy/go-gitlab => github.com/xanzy/go-gitlab v0.16.0

replace github.com/xiang90/probing => github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2

replace go.etcd.io/bbolt => go.etcd.io/bbolt v1.3.2

replace go.opencensus.io => go.opencensus.io v0.19.0

replace go.uber.org/multierr => go.uber.org/multierr v1.1.0

replace go.uber.org/zap => go.uber.org/zap v1.10.0

replace golang.org/x/build => golang.org/x/build v0.0.0-20190314133821-5284462c4bec

replace golang.org/x/crypto => golang.org/x/crypto v0.0.0-20190404164418-38d8ce5564a5

replace golang.org/x/lint => golang.org/x/lint v0.0.0-20190301231843-5614ed5bae6f

replace golang.org/x/oauth2 => golang.org/x/oauth2 v0.0.0-20190226205417-e64efc72b421

replace golang.org/x/time => golang.org/x/time v0.0.0-20181108054448-85acf8d2951c

replace golang.org/x/tools => golang.org/x/tools v0.0.0-20190312170243-e65039ee4138

replace google.golang.org/api => google.golang.org/api v0.1.0

replace google.golang.org/genproto => google.golang.org/genproto v0.0.0-20190307195333-5fe7a883aa19

replace google.golang.org/grpc => google.golang.org/grpc v1.21.0

replace gopkg.in/alecthomas/kingpin.v2 => gopkg.in/alecthomas/kingpin.v2 v2.2.6

replace gopkg.in/asn1-ber.v1 => gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d

replace gopkg.in/mgo.v2 => gopkg.in/mgo.v2 v2.0.0-20180705113604-9856a29383ce

replace gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.2

replace gotest.tools => gotest.tools v2.2.0+incompatible

replace honnef.co/go/tools => honnef.co/go/tools v0.0.0-20190106161140-3f1c8253044a

replace k8s.io/api => k8s.io/api v0.0.0-20190222213804-5cb15d344471

replace k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20180516022032-3492ef8dace1

replace k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20190313123343-44a48934c135

replace k8s.io/client-go => k8s.io/client-go v0.0.0-20180517072830-4bb327ea2f8e

replace sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0

replace github.com/mobiledgex/yaml/v2 => github.com/mobiledgex/yaml/v2 v2.2.4

replace github.com/kr/pty => github.com/kr/pty v1.1.3

replace github.com/pion/webrtc/v2 => github.com/pion/webrtc/v2 v2.0.7

replace golang.org/x/text => golang.org/x/text v0.3.1-0.20180807135948-17ff2d5776d2

replace github.com/uber/prototool => github.com/uber/prototool v1.8.0
