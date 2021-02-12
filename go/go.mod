module github.com/inverse-inc/packetfence/go

go 1.15

require (
	github.com/Azure/azure-sdk-for-go v40.6.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.10
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.3
	github.com/DataDog/datadog-go v3.5.0+incompatible // indirect
	github.com/DataDog/zstd v1.4.5 // indirect
	github.com/OneOfOne/xxhash v1.2.7
	github.com/Sereal/Sereal v0.0.0-20200729022450-08708a3c86f3
	github.com/Shopify/sarama v1.24.0 // indirect
	github.com/alangpierce/go-forceexport v0.0.0-20160317203124-8f1d6941cd75 // indirect
	github.com/aws/aws-sdk-go v1.35.9
	github.com/caddyserver/caddy v1.0.3 // indirect
	github.com/captncraig/cors v0.0.0-20170507232344-153f484dcf3d
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/cevaris/ordered_map v0.0.0-20171019141434-01ce2b16ad4f
	github.com/cheekybits/genny v1.0.0 // indirect
	github.com/coredns/caddy v1.1.0
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.15+incompatible // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20190719114852-fd7a80b32e1f
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/dnstap/golang-dnstap v0.2.2
	github.com/domodwyer/mailyak v3.1.1+incompatible // indirect
	github.com/dustin/go-humanize v1.0.0
	github.com/farsightsec/golang-framestream v0.3.0
	github.com/fdurand/arp v0.0.0-20180807174648-27b38d3af1be
	github.com/fdurand/go-cache v0.0.0-20180104143916-cf0198ac7d92
	github.com/flynn/go-shlex v0.0.0-20150515145356-3f9db97f8568
	github.com/gavv/httpexpect/v2 v2.1.0
	github.com/gdey/jsonpath v0.0.0-20151203210429-124c978a1ffc
	github.com/gin-gonic/gin v1.6.2
	github.com/go-acme/lego v2.5.0+incompatible
	github.com/go-acme/lego/v3 v3.2.0 // indirect
	github.com/go-errors/errors v1.0.1
	github.com/go-redis/redis v0.0.0-20190325112110-a679e614427a
	github.com/go-sql-driver/mysql v1.4.1
	github.com/go-test/deep v1.0.5
	github.com/goji/httpauth v0.0.0-20160601135302-2da839ab0f4d
	github.com/golang-collections/go-datastructures v0.0.0-20150211160725-59788d5eb259 // indirect
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.4.0
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/rpc v0.0.0-20160927134711-22c016f3df3f
	github.com/gorilla/schema v1.1.0
	github.com/gorilla/websocket v1.4.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.11.3 // indirect
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20180507213350-8e809c8a8645
	github.com/hanwen/go-fuse/v2 v2.0.3
	github.com/hashicorp/go-syslog v1.0.0
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hpcloud/tail v1.0.0
	github.com/imdario/mergo v0.3.9 // indirect
	github.com/inconshreveable/log15 v0.0.0-20171019012758-0decfc6c20d9
	github.com/infobloxopen/go-trees v0.0.0-20190313150506-2af4e13f9062
	github.com/inverse-inc/dhcp4 v0.0.0-20200625173842-2c4d1e50d7ca
	github.com/inverse-inc/go-cache v2.1.0+incompatible // indirect
	github.com/inverse-inc/go-ipset v0.0.0-20190925174109-4d5749cc4aa6
	github.com/inverse-inc/go-radius v0.0.0-20201019132414-82756e2d8d47
	github.com/jcuga/golongpoll v1.1.0
	github.com/jimstudt/http-authentication v0.0.0-20140401203705-3eca13d6893a
	github.com/jinzhu/gorm v1.9.11
	github.com/julienschmidt/httprouter v1.3.0
	github.com/julsemaan/certmagic v0.6.3-0.20191015203349-067e102ae4ff
	github.com/klauspost/cpuid v1.2.1
	github.com/knq/pemutil v0.0.0-20181215144041-fb6fad722528
	github.com/kr/pretty v0.2.0
	github.com/lucas-clemente/quic-go v0.10.2
	github.com/marten-seemann/chacha20 v0.2.0 // indirect
	github.com/marten-seemann/qpack v0.1.0 // indirect
	github.com/marten-seemann/qtls v0.4.1 // indirect
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1
	github.com/mdlayher/ethernet v0.0.0-20170707213343-e72cf8343052
	github.com/mdlayher/raw v0.0.0-20171214195253-9df8b4265df2
	github.com/mediocregopher/radix.v2 v0.0.0-20180603022615-94360be26253
	github.com/mholt/caddy v0.9.5 // indirect
	github.com/mholt/certmagic v0.8.3 // indirect
	github.com/miekg/dns v1.1.34
	github.com/naoina/toml v0.1.1
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d
	github.com/nxadm/tail v1.4.4
	github.com/opentracing/opentracing-go v1.2.0
	github.com/openzipkin-contrib/zipkin-go-opentracing v0.4.5
	github.com/openzipkin/zipkin-go v0.2.2
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/philhofer/fwd v1.0.0 // indirect
	github.com/pierrec/lz4 v2.3.0+incompatible // indirect
	github.com/prometheus/client_golang v1.8.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.14.0
	github.com/robfig/cron/v3 v3.0.1
	github.com/russross/blackfriday v1.5.2
	github.com/simon/go-netadv v0.0.0-20170602081515-fe67988531c7
	github.com/sparrc/go-ping v0.0.0-20190613174326-4e5b6552494c
	github.com/tmc/grpc-websocket-proxy v0.0.0-20200122045848-3419fae592fc // indirect
	go.etcd.io/etcd v0.5.0-alpha.5.0.20200306183522-221f0cc107cb
	go.uber.org/zap v1.14.1 // indirect
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/net v0.0.0-20200707034311-ab3426394381
	golang.org/x/sys v0.0.0-20201015000850-e3ed0017c211
	golang.org/x/text v0.3.3
	google.golang.org/api v0.29.0
	google.golang.org/grpc v1.29.1
	gopkg.in/DataDog/dd-trace-go.v1 v1.27.1
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/alexcesaro/statsd.v2 v2.0.0-20160320182110-7fea3f0d2fab
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/ldap.v2 v2.0.0-20171123045618-bb7a9ca6e4fb
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/client-go v0.19.2
	k8s.io/klog v1.0.0
	layeh.com/radius v0.0.0-20180123164351-38e2cda15058 // indirect
	software.sslmate.com/src/go-pkcs12 v0.0.0-20190322163127-6e380ad96778
)

replace github.com/inverse-inc/packetfence => ../

replace github.com/inverse-inc/packetfence/go => ./

replace github.com/inverse-inc/packetfence/go/caddy/caddy => ./go/caddy/caddy
