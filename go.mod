module github.com/ethereum/go-ethereum

go 1.26.0

require (
	bazil.org/fuse v0.0.0-20160811212531-371fbbdaa898
	github.com/Azure/azure-storage-blob-go v0.7.0
	github.com/ProtonMail/go-crypto v1.5.2
	github.com/aristanetworks/goarista v0.0.0-20170210015632-ea17b1a17847
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
	github.com/cespare/cp v0.1.0
	github.com/davecgh/go-spew v1.1.1
	github.com/edsrzf/mmap-go v0.0.0-20160512033002-935e0e8a636c
	github.com/elastic/gosigar v0.8.1-0.20180123065306-a3814ce5008e
	github.com/fatih/color v1.3.0
	github.com/gizak/termui v2.2.1-0.20170117222342-991cd3d38091+incompatible
	github.com/go-stack/stack v1.8.0
	github.com/golang/protobuf v1.5.4
	github.com/golang/snappy v0.0.0-20180518054509-2e65f85255db
	github.com/hashicorp/golang-lru v0.5.1
	github.com/huin/goupnp v0.0.0-20161224104101-679507af18f3
	github.com/influxdata/influxdb v1.8.3
	github.com/jackpal/go-nat-pmp v1.0.2-0.20160603034137-1fa385a6f458
	github.com/julienschmidt/httprouter v1.2.0
	github.com/karalabe/hid v0.0.0-20170821103837-f00545f9f374
	github.com/mattn/go-colorable v0.0.9
	github.com/naoina/toml v0.1.1-0.20170410220130-ac014c6b6502
	github.com/olekukonko/tablewriter v0.0.0-20170128050532-febf2d34b54a
	github.com/pborman/uuid v0.0.0-20170112150404-1b00554d8222
	github.com/peterh/liner v1.0.1-0.20180619022028-8c1271fcf47f
	github.com/prometheus/tsdb v0.7.1
	github.com/rjeczalik/notify v0.9.1
	github.com/robertkrimen/otto v0.0.0-20170205013659-6a77b7cbc37d
	github.com/rs/cors v1.7.0
	github.com/stretchr/testify v1.8.2
	github.com/syndtr/goleveldb v0.0.0-20180128140416-211f78098806
	golang.org/x/crypto v0.58.1-0.20261009181718-2f1f834330b2
	golang.org/x/net v0.62.0
	golang.org/x/sync v0.24.0
	golang.org/x/sys v0.49.0
	golang.org/x/tools v0.51.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/fatih/set.v0 v0.0.0-00010101000000-000000000000
	gopkg.in/karalabe/cookiejar.v2 v2.0.0-20150724131613-8dcd6a7f4951
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
	gopkg.in/olebedev/go-duktape.v3 v3.0.0-20171220121914-9af39127cb02
	gopkg.in/urfave/cli.v1 v1.20.0
)

require (
	github.com/Azure/azure-pipeline-go v0.2.3 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.24 // indirect
	github.com/StackExchange/wmi v0.0.0-20180116203802-5d049714c4a6 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/go-ole/go-ole v1.2.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/kr/text v0.1.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/maruel/panicparse v0.0.0-20160720141634-ad661195ed0e // indirect
	github.com/maruel/ut v1.0.2 // indirect
	github.com/mattn/go-ieproxy v0.0.1 // indirect
	github.com/mattn/go-isatty v0.0.4 // indirect
	github.com/mattn/go-runewidth v0.0.3 // indirect
	github.com/mitchellh/go-wordwrap v0.0.0-20150314170334-ad45545899c7 // indirect
	github.com/naoina/go-stringutil v0.1.0 // indirect
	github.com/nsf/termbox-go v0.0.0-20170211012700-3540b76b9c77 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/onsi/gomega v1.44.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/protobuf v1.36.7 // indirect
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace gopkg.in/fatih/set.v0 => ./internal/thirdparty/fatih-set
