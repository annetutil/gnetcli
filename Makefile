mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
protoc_cmd := python3 -m grpc_tools.protoc

all: build proto testrace

build:
	go build ./...

build-docker:
	docker build ./

proto:
	protoc -I '${CURDIR}/pkg/server/proto/'  \
		 --go_out='${CURDIR}/pkg/server/proto/' \
		 --go-grpc_out='${CURDIR}/pkg/server/proto/' \
		 --go_opt=paths=source_relative \
		 --go-grpc_opt=paths=source_relative \
		 '${CURDIR}/pkg/server/proto/server.proto';
	$(protoc_cmd) -I '${CURDIR}/pkg/server/proto/' \
		 --python_out '${CURDIR}/pkg/server/proto/'  \
		 --pyi_out '${CURDIR}/pkg/server/proto/'  \
		 --grpc_python_out '${CURDIR}/pkg/server/proto/'  \
		 '${CURDIR}/pkg/server/proto/server.proto';
	# https://github.com/protocolbuffers/protobuf/issues/5374
	perl -pi -e 's,import server_pb2 as server__pb2,from . import server_pb2 as server__pb2,' '${CURDIR}/pkg/server/proto/server_pb2_grpc.py'

testrace:
	go test -v -race -cpu 1,4 ./...

clean:
	go clean -i ./...


.PHONY: \
	all \
	clean
