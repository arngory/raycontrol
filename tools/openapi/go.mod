// The OpenAPI generator (integrations-v1 §5), in a module of its own: its
// dependencies would otherwise move protoc-gen-go and the Go code it makes.
// Used through scripts/gen.sh with -modfile=tools/openapi/go.mod.
module github.com/arngory/raycontrol/tools/openapi

go 1.26.0

tool connectrpc.com/protoc-gen-connect-openapi

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.2 // indirect
	buf.build/go/protovalidate v1.4.0 // indirect
	cel.dev/cel-go v0.33.2 // indirect
	cel.dev/expr v0.25.3 // indirect
	connectrpc.com/protoc-gen-connect-openapi v0.30.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.6.1 // indirect
	github.com/gobwas/glob v1.1.0 // indirect
	github.com/google/gnostic v0.7.1 // indirect
	github.com/google/gnostic-models v0.7.1 // indirect
	github.com/lmittmann/tint v1.2.1 // indirect
	github.com/pb33f/go-yaml v0.1.1 // indirect
	github.com/pb33f/jsonpath v0.8.5 // indirect
	github.com/pb33f/libopenapi v0.42.3 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.2 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/exp v0.0.0-20261106112924-d498a4c2cc9a // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261104224025-d1e00e9f33ab // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261104224025-d1e00e9f33ab // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
