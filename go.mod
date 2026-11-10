module github.com/php/tamis

go 1.27.3

require (
	github.com/alpha-omega-security/harness v0.1.21
	github.com/git-pkgs/cwe v0.1.1
	github.com/stretchr/testify v1.12.1
	go.yaml.in/yaml/v3 v3.0.6
	golang.org/x/crypto v0.58.0
	golang.org/x/sync v0.24.0
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/bitfield/gotestdox v0.2.3 // indirect
	github.com/dnephin/pflag v1.0.7 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/git-pkgs/skills v0.2.1 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3 // indirect
	golang.org/x/exp/typeparams v0.0.0-20261106192419-47ce03d25ef0 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261021172232-6cd571d43fbb // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.9.0 // indirect
	gotest.tools/gotestsum v1.13.0 // indirect
	honnef.co/go/tools v0.8.2 // indirect
)

tool (
	golang.org/x/vuln/cmd/govulncheck
	gotest.tools/gotestsum
	honnef.co/go/tools/cmd/staticcheck
)
