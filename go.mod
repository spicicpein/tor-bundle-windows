module tor-bundle-windows

go 1.22.2

replace golang.org/x/crypto => github.com/golang/crypto v0.0.0-20220313003712-b769efc7c000

replace golang.org/x/sys => github.com/golang/sys v0.0.0-20220310020820-b874c991c1a5

replace golang.org/x/net => github.com/golang/net v0.0.0-20210525063256-abc453219eb5

replace golang.org/x/term => github.com/golang/term v0.0.0-20201126162022-7de9c90e9dd1

replace gopkg.in/yaml.v3 => github.com/go-yaml/yaml v0.0.0-20200313102051-9f266ea9e77c

replace golang.org/x/text => github.com/golang/text v0.3.6

replace gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20161208181325-20d25e280405

replace golang.org/x/tools => github.com/golang/tools v0.0.0-20180917221912-90fa682c2a6e

replace golang.org/x/mod => github.com/golang/mod v0.0.0-20190513183733-4bf6d317e70e

replace golang.org/x/xerrors => github.com/golang/xerrors v0.0.0-20191204190536-9bdfabe68543

require (
	github.com/cretz/bine v0.2.0
	github.com/gen2brain/go-libtor v1.2.0
)

require (
	golang.org/x/crypto v0.0.0-20220313003712-b769efc7c000 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/sys v0.0.0-20220310020820-b874c991c1a5 // indirect
)

replace github.com/gen2brain/go-libtor => github.com/spicicpein/go-libtor v1.2.1-0.20260722060237-8ac7fa38eca9
