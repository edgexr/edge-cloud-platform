module github.com/edgexr/edge-cloud-platform

go 1.18

require (
	cloud.google.com/go v0.39.0
	github.com/AsGz/geo v0.0.0-20170331085501-324ae0e80045
	github.com/Bose/minisentinel v0.0.0-20200130220412-917c5a9223bb
	github.com/Shopify/sarama v1.22.2-0.20190604114437-cd910a683f9f
	github.com/agnivade/levenshtein v1.0.1
	github.com/alicebob/miniredis/v2 v2.18.0
	github.com/asaskevich/govalidator v0.0.0-20200428143746-21a406dcc535
	github.com/atlassian/go-artifactory/v2 v2.3.0
	github.com/cespare/xxhash/v2 v2.1.2
	github.com/cloudflare/cloudflare-go v0.13.4
	github.com/codeskyblue/go-sh v0.0.0-20170112005953-b097669b1569
	github.com/coreos/etcd v3.3.10+incompatible
	github.com/creack/pty v1.1.10
	github.com/davecgh/go-spew v1.1.1
	github.com/daviddengcn/go-colortext v0.0.0-20171126034257-17e75f6184bc
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/elastic/go-elasticsearch/v7 v7.5.0
	github.com/go-chef/chef v0.23.1
	github.com/go-openapi/errors v0.19.7
	github.com/go-openapi/loads v0.19.5
	github.com/go-openapi/spec v0.19.8
	github.com/go-openapi/strfmt v0.19.5
	github.com/go-openapi/swag v0.19.9
	github.com/go-openapi/validate v0.19.11
	github.com/gogo/gateway v1.0.0
	github.com/gogo/googleapis v1.1.0
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.4.2
	github.com/google/go-cmp v0.4.0
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.1
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.14.5
	github.com/hashicorp/vault/api v1.0.5-0.20200317185738-82f498082f02
	github.com/influxdata/influxdb v1.7.7
	github.com/jaegertracing/jaeger v1.21.0
	github.com/jarcoal/httpmock v1.0.6
	github.com/jinzhu/gorm v1.9.10
	github.com/jung-kurt/gofpdf v1.16.2
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/labstack/echo v0.0.0-20180911044237-1abaa3049251
	github.com/lib/pq v1.5.2
	github.com/miekg/dns v1.1.27
	github.com/mileusna/useragent v1.0.2
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
	github.com/segmentio/ksuid v1.0.2
	github.com/shirou/gopsutil v2.20.4+incompatible
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.1
	github.com/test-go/testify v1.1.4
	github.com/tmc/scp v0.0.0-20170824174625-f7b48647feef
	github.com/trustelem/zxcvbn v1.0.1
	github.com/uber/jaeger-client-go v2.23.1+incompatible
	github.com/uber/jaeger-lib v2.4.0+incompatible
	github.com/vmware/go-vcloud-director/v2 v2.11.0
	github.com/wcharczuk/go-chart/v2 v2.1.0
	github.com/xanzy/go-gitlab v0.16.0
	github.com/xtaci/smux v1.3.6
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	golang.org/x/tools v0.0.0-20210106214847-113979e3529a
	google.golang.org/api v0.14.0
	google.golang.org/grpc v1.29.1
	gopkg.in/ldap.v3 v3.0.3
	gopkg.in/yaml.v2 v2.4.0
	gortc.io/stun v1.21.0
	//	k8s.io/api v0.0.0-20180516102522-184e700b32b7
	k8s.io/api v0.17.3
	k8s.io/apimachinery v0.17.3
	k8s.io/cli-runtime v0.0.0-20190313123343-44a48934c135
	k8s.io/client-go v0.17.3
)

require (
	github.com/go-redis/redis/v8 v8.11.5
	github.com/golang-jwt/jwt/v4 v4.4.1
	github.com/swaggest/jsonschema-go v0.3.34
	github.com/swaggest/openapi-go v0.2.18
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/DataDog/zstd v1.4.4 // indirect
	github.com/HdrHistogram/hdrhistogram-go v0.9.0 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/Sirupsen/logrus v1.6.0 // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/alicebob/gopher-json v0.0.0-20200520072559-a9ecdc9d1d3a // indirect
	github.com/araddon/dateparse v0.0.0-20190622164848-0fb0a474d195 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/codegangsta/inject v0.0.0-20150114235600-33e0aa1cb7c0 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/denisenkom/go-mssqldb v0.0.0-20190905012053-7920e8ef8898 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2 v1.4.0 // indirect
	github.com/docker/docker v1.13.1 // indirect
	github.com/eapache/go-resiliency v1.2.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20180814174437-776d5712da21 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/frankban/quicktest v1.10.0 // indirect
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32 // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/go-openapi/analysis v0.19.10 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.3 // indirect
	github.com/go-openapi/runtime v0.19.16 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/go-test/deep v1.0.2 // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/groupcache v0.0.0-20190702054246-869f871628b6 // indirect
	github.com/golang/snappy v0.0.1 // indirect
	github.com/golangplus/testing v0.0.0-20180327235837-af21d9c3145e // indirect
	github.com/gomodule/redigo v1.8.8 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/googleapis/gax-go/v2 v2.0.5 // indirect
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/go-multierror v1.1.0 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.6 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/hashicorp/go-version v1.2.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/vault/sdk v0.1.14-0.20200429182704-29fce8f27ce4 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jcelliott/lumber v0.0.0-20160324203708-dd349441af25 // indirect
	github.com/jcmturner/gofork v1.0.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.3 // indirect
	github.com/kr/pretty v0.2.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/labstack/gommon v0.0.0-20180312174116-6fe1405d73ec // indirect
	github.com/mailru/easyjson v0.7.1 // indirect
	github.com/mattn/go-colorable v0.1.6 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/peterhellberg/link v1.1.0 // indirect
	github.com/pierrec/lz4 v2.5.2+incompatible // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/procfs v0.1.3 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20190826022208-cac0b30c2563 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/swaggest/refl v1.0.2 // indirect
	github.com/ugorji/go/codec v1.2.7 // indirect
	github.com/valyala/bytebufferpool v0.0.0-20160817181652-e746df99fe4a // indirect
	github.com/valyala/fasttemplate v0.0.0-20170224212429-dcecefd839c4 // indirect
	github.com/yuin/gopher-lua v0.0.0-20210529063254-f4c35e4016d9 // indirect
	go.mongodb.org/mongo-driver v1.3.4 // indirect
	go.opencensus.io v0.22.2 // indirect
	go.uber.org/atomic v1.6.0 // indirect
	go.uber.org/multierr v1.5.0 // indirect
	golang.org/x/image v0.0.0-20200927104501-e162460cd6b5 // indirect
	golang.org/x/mod v0.3.0 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	golang.org/x/term v0.0.0-20201126162022-7de9c90e9dd1 // indirect
	golang.org/x/text v0.3.6 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/appengine v1.6.0 // indirect
	google.golang.org/genproto v0.0.0-20200305110556-506484158171 // indirect
	google.golang.org/protobuf v1.23.0 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/jcmturner/aescts.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/dnsutils.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/gokrb5.v7 v7.2.3 // indirect
	gopkg.in/jcmturner/rpc.v1 v1.1.0 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog v1.0.0 // indirect
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)

replace github.com/mitchellh/mapstructure => github.com/mobiledgex/mapstructure v1.2.4-0.20200429201435-a2efef9031f5

replace (
	github.com/Sirupsen/logrus => github.com/Sirupsen/logrus v1.6.0
	github.com/Sirupsen/logrus v1.6.0 => github.com/sirupsen/logrus v1.6.0
)

replace github.com/vmware/go-vcloud-director/v2 v2.11.0 => github.com/mobiledgex/go-vcloud-director/v2 v2.11.0-241.2
